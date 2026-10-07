package connection_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/cloudflare/cloudflared/client"
	cmdtunnel "github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/diagnostic"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/origins"
	"github.com/cloudflare/cloudflared/metrics"
	"github.com/cloudflare/cloudflared/orchestration"
	"github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/supervisor"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/cloudflare/cloudflared/tunnelstate"
)

type localFeatures struct{}

func (localFeatures) Snapshot() features.FeatureSnapshot {
	return features.FeatureSnapshot{PostQuantum: features.PostQuantumPrefer, DatagramVersion: features.DatagramV2, FeaturesList: []string{"serialized_headers", "datagram_v2", "allow_remote_config"}, SkipPrechecks: true}
}

type shutdownPeer struct {
	registrationPeer
	entered           chan struct{}
	ack               <-chan struct{}
	unregister        chan struct{}
	unregisterRelease <-chan struct{}
}

func (s shutdownPeer) RegisterConnection(ctx context.Context, auth pogs.TunnelAuth, tunnel uuid.UUID, index byte, options *pogs.ConnectionOptions) (*pogs.ConnectionDetails, error) {
	close(s.entered)
	if s.ack != nil {
		select {
		case <-s.ack:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.registrationPeer.RegisterConnection(ctx, auth, tunnel, index, options)
}
func (s shutdownPeer) UnregisterConnection(ctx context.Context) {
	close(s.unregister)
	if s.unregisterRelease != nil {
		select {
		case <-s.unregisterRelease:
		case <-ctx.Done():
		}
	}
}

func sourceGoAway(c *recordedReadmissionConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := http2.NewFramer(nil, bytes.NewReader(c.responses.Bytes()))
	for {
		frame, err := frames.ReadFrame()
		if err != nil {
			return false
		}
		if _, ok := frame.(*http2.GoAwayFrame); ok {
			return true
		}
	}
}

type globalFixture struct {
	serverCtx context.Context
	grace     chan struct{}
	errors    chan error
	stopped   chan error
	wire      *recordedReadmissionConn
	peer      *http2.ClientConn
	tracker   *eventTracker
}

func startGlobalFixture(t *testing.T, ctx context.Context, period time.Duration) *globalFixture {
	t.Helper()
	serverCtx, cancelServer := context.WithCancel(ctx)
	t.Cleanup(cancelServer)
	log := zerolog.Nop()
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certificateServer.TLS.Certificates
	pool := x509.NewCertPool()
	pool.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certificates, NextProtos: []string{"h2"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	defaultDialer := ingress.NewDialer(ingress.WarpRoutingConfig{})
	originDialer := ingress.NewOriginDialer(ingress.OriginConfig{DefaultDialer: defaultDialer, TCPWriteTimeout: time.Second}, &log)
	rules, err := ingress.ParseIngress(&config.Configuration{Ingress: []config.UnvalidatedIngressRule{{Service: "http_status:203"}}})
	require.NoError(t, err)
	orchestrator, err := orchestration.NewOrchestrator(serverCtx, &orchestration.Config{Ingress: &rules, OriginDialerService: originDialer}, nil, nil, &log)
	require.NoError(t, err)
	registry := prometheus.NewRegistry()
	oldRegisterer := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = registry
	t.Cleanup(func() { prometheus.DefaultRegisterer = oldRegisterer })
	dns := origins.NewStaticDNSResolverService([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")}, defaultDialer, &log, origins.NewMetrics(registry))
	clientConfig, err := client.NewConfig("2026.10.0", "linux_amd64", localFeatures{})
	require.NoError(t, err)
	selector, err := connection.NewProtocolSelector("http2", &log)
	require.NoError(t, err)
	observer := connection.NewObserver(&log)
	tracker := &eventTracker{tunnelstate.NewConnTracker(&log), make(chan connection.Event, 32)}
	observer.RegisterSink(tracker)
	for range 16 {
		observer.RegisterSink(connection.EventSinkFunc(func(connection.Event) {}))
	}
	observer.SendURL("https://synthetic.invalid")
	waitEvent(t, ctx, tracker.events, connection.SetURL)
	grace := make(chan struct{})
	tunnelConfig := &supervisor.TunnelConfig{ClientConfig: clientConfig, GracePeriod: period, EdgeAddrs: []string{listener.Addr().String()}, HAConnections: 1, Log: &log, Observer: observer, Retries: 0, MaxEdgeAddrRetries: 8, NamedTunnel: &connection.TunnelProperties{}, ProtocolSelector: selector, EdgeTLSConfigs: map[connection.Protocol]*tls.Config{connection.HTTP2: {RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}}}, OriginDNSService: dns, OriginDialerService: originDialer, RPCTimeout: time.Second, NoPrechecks: true}
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	wg.Add(1)
	go func() {
		defer wg.Done()
		errors <- supervisor.StartTunnelDaemon(serverCtx, tunnelConfig, orchestrator, signal.New(make(chan struct{})), grace)
	}()
	stopped := make(chan error, 1)
	go func() { stopped <- cmdtunnel.RustInteropWaitToShutdown(&wg, cancelServer, errors, grace, period, &log) }()
	edgeSocket, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = edgeSocket.Close() })
	peerWire := &recordedReadmissionConn{recordedH2Conn: &recordedH2Conn{Conn: edgeSocket}, changed: make(chan struct{}, 1)}
	peer, err := (&http2.Transport{}).NewClientConn(peerWire)
	require.NoError(t, err)
	return &globalFixture{serverCtx, grace, errors, stopped, peerWire, peer, tracker}
}

func TestPinnedGoGlobalH2GraceLateAckAndDeadline(t *testing.T) {
	ctx, cancelTest := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelTest()
	period := 500 * time.Millisecond
	fixture := startGlobalFixture(t, ctx, period)
	serverCtx, grace, stopped, peerWire, peer, tracker := fixture.serverCtx, fixture.grace, fixture.stopped, fixture.wire, fixture.peer, fixture.tracker
	firstUnregister := make(chan struct{})
	first := startControlAttempt(t, ctx, peer, shutdownPeer{entered: make(chan struct{}), unregister: firstUnregister})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	ack := make(chan struct{})
	entered := make(chan struct{})
	secondUnregister := make(chan struct{})
	second := startControlAttempt(t, ctx, peer, shutdownPeer{entered: entered, ack: ack, unregister: secondUnregister})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	started := time.Now()
	close(grace)
	select {
	case <-firstUnregister:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	close(ack)
	waitEvent(t, ctx, tracker.events, connection.Connected)
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	select {
	case <-secondUnregister:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, "END_STREAM", peerWire.waitTermination(t, ctx, 1))
	require.Equal(t, "END_STREAM", peerWire.waitTermination(t, ctx, 3))
	_ = waitError(t, ctx, first.rpcDone)
	_ = waitError(t, ctx, second.rpcDone)
	require.False(t, sourceGoAway(peerWire), "control completion/global grace must not send an early GOAWAY")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://synthetic.invalid/during-global-grace", nil)
	require.NoError(t, err)
	response, err := peer.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, 203, response.StatusCode)
	_, err = io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	select {
	case <-serverCtx.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.GreaterOrEqual(t, time.Since(started), period)
	require.NoError(t, waitError(t, ctx, stopped))
	require.Zero(t, tracker.tracker.CountActiveConns())
	t.Log("actual StartTunnelDaemon + CLI wait: late ACK after grace is admitted then unregistered, both controls FIN, new HTTP works without GOAWAY until global deadline cancels context")
}

func TestPinnedGoGlobalH2EarlyGraceBeforeInitialAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	period := 2 * time.Second
	fixture := startGlobalFixture(t, ctx, period)
	ack := make(chan struct{})
	entered := make(chan struct{})
	unregistered := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: entered, ack: ack, unregister: unregistered})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	started := time.Now()
	close(fixture.grace)
	require.NoError(t, waitError(t, ctx, fixture.stopped))
	require.Less(t, time.Since(started), period, "initialization's graceful exit must shorten global grace")
	require.Error(t, fixture.serverCtx.Err())
	_ = waitError(t, ctx, attempt.rpcDone)
	close(ack)
	require.Zero(t, fixture.tracker.tracker.CountActiveConns())
	select {
	case <-unregistered:
		t.Fatal("no decoded initial ACK must not invent unregister")
	default:
	}
	for {
		select {
		case event := <-fixture.tracker.events:
			require.NotEqual(t, connection.Connected, event.EventType)
		default:
			return
		}
	}
}

func TestPinnedGoGlobalH2PeerClosureShortensGrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	period := 2 * time.Second
	fixture := startGlobalFixture(t, ctx, period)
	unregistered := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: make(chan struct{}), unregister: unregistered})
	waitEvent(t, ctx, fixture.tracker.events, connection.Connected)
	started := time.Now()
	close(fixture.grace)
	select {
	case <-unregistered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, "END_STREAM", fixture.wire.waitTermination(t, ctx, 1))
	_ = waitError(t, ctx, attempt.rpcDone)
	require.NoError(t, fixture.wire.Close())
	require.NoError(t, waitError(t, ctx, fixture.stopped))
	require.Less(t, time.Since(started), period)
	require.Error(t, fixture.serverCtx.Err())
	t.Log("actual daemon transport completion wakes CLI grace waiter and cancels global context before deadline")
}

func TestPinnedGoGlobalH2ServiceErrorDuringGraceShortensDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	period := 2 * time.Second
	fixture := startGlobalFixture(t, ctx, period)
	unregistered := make(chan struct{})
	release := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: make(chan struct{}), unregister: unregistered, unregisterRelease: release})
	waitEvent(t, ctx, fixture.tracker.events, connection.Connected)
	started := time.Now()
	close(fixture.grace)
	select {
	case <-unregistered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	fixture.errors <- fmt.Errorf("synthetic service failure during grace")
	require.NoError(t, waitError(t, ctx, fixture.stopped), "service error after grace was selected is intentionally discarded")
	require.Less(t, time.Since(started), period)
	require.Error(t, fixture.serverCtx.Err())
	_ = waitError(t, ctx, attempt.rpcDone)
	close(release)
}

func TestPinnedGoGlobalH2BlockedUnregisterStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	period := 200 * time.Millisecond
	fixture := startGlobalFixture(t, ctx, period)
	unregistered := make(chan struct{})
	release := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: make(chan struct{}), unregister: unregistered, unregisterRelease: release})
	waitEvent(t, ctx, fixture.tracker.events, connection.Connected)
	started := time.Now()
	close(fixture.grace)
	select {
	case <-unregistered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, waitError(t, ctx, fixture.stopped))
	require.GreaterOrEqual(t, time.Since(started), period)
	require.Less(t, time.Since(started), period+time.Second, "one global deadline must not wait a second full RPC grace")
	require.Error(t, fixture.serverCtx.Err())
	_ = waitError(t, ctx, attempt.rpcDone)
	close(release)
}

func TestPinnedGoGlobalH2ZeroGraceCancelsImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := startGlobalFixture(t, ctx, 0)
	unregistered := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: make(chan struct{}), unregister: unregistered})
	waitEvent(t, ctx, fixture.tracker.events, connection.Connected)
	started := time.Now()
	close(fixture.grace)
	require.NoError(t, waitError(t, ctx, fixture.stopped))
	require.Less(t, time.Since(started), time.Second)
	require.Error(t, fixture.serverCtx.Err())
	_ = waitError(t, ctx, attempt.rpcDone)
}

func TestPinnedGoGlobalH2RegistrationErrorArrivesOnlyAfterPeerClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := startGlobalFixture(t, ctx, 2*time.Second)
	entered := make(chan struct{})
	attempt := startControlAttempt(t, ctx, fixture.peer, preAckPeer{mode: "reject", entered: entered})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, "END_STREAM", fixture.wire.waitTermination(t, ctx, 1))
	_ = waitError(t, ctx, attempt.rpcDone)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://synthetic.invalid/after-registration-rejection", nil)
	require.NoError(t, err)
	response, err := fixture.peer.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, 203, response.StatusCode)
	_, err = io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.NoError(t, fixture.serverCtx.Err(), "registration rejection alone must not cancel global lifecycle")
	require.NoError(t, fixture.wire.Close())
	result := waitError(t, ctx, fixture.stopped)
	var failure connection.ServerRegisterTunnelError
	require.ErrorAs(t, result, &failure)
	require.True(t, failure.Permanent)
	require.EqualError(t, result, "synthetic registration rejection")
	require.Error(t, fixture.serverCtx.Err())
}

func TestPinnedGoSignalForceChild(t *testing.T) {
	if os.Getenv("CLOUDFLARED_RUST_SIGNAL_CHILD") != "1" {
		t.Skip("disposable signal subprocess")
	}
	grace := make(chan struct{})
	close(grace)
	cmdtunnel.RustInteropWaitForSignal(grace)
	fmt.Println("source_signal_handler_unsubscribed")
	reader := bufio.NewReader(os.Stdin)
	for {
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		fmt.Println("source_child_alive")
	}
}

func TestPinnedGoSignalStopPreservesInheritedIgnoredInterrupt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "trap '' INT; exec \"$0\" -test.run=^TestPinnedGoSignalForceChild$ -test.v", os.Args[0])
	command.Env = append(os.Environ(), "CLOUDFLARED_RUST_SIGNAL_CHILD=1")
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	armed := false
	for scanner.Scan() {
		if scanner.Text() == "source_signal_handler_unsubscribed" {
			armed = true
			break
		}
	}
	require.True(t, armed)
	require.NoError(t, command.Process.Signal(syscall.SIGINT))
	_, err = io.WriteString(stdin, "check alive\n")
	require.NoError(t, err)
	require.True(t, scanner.Scan())
	require.Equal(t, "source_child_alive", scanner.Text())
	require.NoError(t, command.Process.Signal(syscall.SIGTERM))
	require.Error(t, command.Wait())
	status := command.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGTERM, status.Signal())
	t.Log("source signal.Stop restores inherited SIG_IGN for INT while TERM keeps actual default termination")
}

func TestPinnedGoSignalAfterSourceHandlerExitUsesDefaultAction(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPinnedGoSignalForceChild$", "-test.v")
		command.Env = append(os.Environ(), "CLOUDFLARED_RUST_SIGNAL_CHILD=1")
		stdout, err := command.StdoutPipe()
		require.NoError(t, err)
		stdin, err := command.StdinPipe()
		require.NoError(t, err)
		defer stdin.Close()
		require.NoError(t, command.Start())
		t.Cleanup(func() {
			_ = stdin.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
		})
		scanner := bufio.NewScanner(stdout)
		armed := false
		for scanner.Scan() {
			if scanner.Text() == "source_signal_handler_unsubscribed" {
				armed = true
				break
			}
		}
		require.True(t, armed)
		require.NoError(t, command.Process.Signal(sig))
		err = command.Wait()
		require.Error(t, err)
		status := command.ProcessState.Sys().(syscall.WaitStatus)
		require.True(t, status.Signaled())
		require.Equal(t, sig, status.Signal())
	}
	t.Log("actual source waitForSignal exit unsubscribes; a subsequent SIGINT/SIGTERM terminates owned child by OS default, not another graceful pass")
}

func TestPinnedGoGlobalMetricsRemainDuringGrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := startGlobalFixture(t, ctx, time.Second)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	address := listener.Addr().String()
	log := zerolog.Nop()
	done := make(chan error, 1)
	handler := diagnostic.NewDiagnosticHandler(&log, time.Second, nil, uuid.Nil, uuid.Nil, fixture.tracker.tracker, map[string]string{}, nil)
	go func() {
		done <- metrics.ServeMetrics(listener, fixture.serverCtx, metrics.Config{ReadyServer: metrics.NewReadyServer(uuid.Nil, fixture.tracker.tracker), DiagnosticHandler: handler}, &log)
	}()
	unregistered := make(chan struct{})
	startControlAttempt(t, ctx, fixture.peer, shutdownPeer{entered: make(chan struct{}), unregister: unregistered})
	waitEvent(t, ctx, fixture.tracker.events, connection.Connected)
	httpClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}
	fetch := func(path string) (int, string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		require.NoError(t, err)
		response, err := httpClient.Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		return response.StatusCode, string(body)
	}
	status, body := fetch("/ready")
	require.Equal(t, 200, status)
	require.Contains(t, body, `"readyConnections":1`)
	close(fixture.grace)
	select {
	case <-unregistered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitEvent(t, ctx, fixture.tracker.events, connection.Unregistering)
	status, body = fetch("/ready")
	require.Equal(t, 503, status)
	require.Contains(t, body, `"readyConnections":0`)
	status, _ = fetch("/metrics")
	require.Equal(t, 200, status)
	require.NoError(t, waitError(t, ctx, fixture.stopped))
	require.NoError(t, waitError(t, ctx, done))
	_, err = httpClient.Get("http://" + address + "/metrics")
	require.Error(t, err)
	t.Log("actual source metrics server context survives grace; readiness follows unregister; listener closes at runtime termination")
}
