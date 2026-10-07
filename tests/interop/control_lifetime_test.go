package connection_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/connection"
	cfdquic "github.com/cloudflare/cloudflared/quic"
	"github.com/cloudflare/cloudflared/tracing"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	rpcquic "github.com/cloudflare/cloudflared/tunnelrpc/quic"
	"github.com/cloudflare/cloudflared/tunnelstate"
)

type eofIO struct {
	io.ReadWriteCloser
	eof  chan struct{}
	once sync.Once
}

func (s *eofIO) Read(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(p)
	if err == io.EOF {
		s.once.Do(func() { close(s.eof) })
	}
	return n, err
}

type eventTracker struct {
	tracker *tunnelstate.ConnTracker
	events  chan connection.Event
}

func (s *eventTracker) OnTunnelEvent(e connection.Event) {
	if e.EventType != connection.SetURL {
		s.tracker.OnTunnelEvent(e)
	}
	s.events <- e
}
func waitEvent(t *testing.T, ctx context.Context, events <-chan connection.Event, kind connection.Status) {
	t.Helper()
	select {
	case event := <-events:
		require.Equal(t, kind, event.EventType)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type connectedFuse struct{}

func (connectedFuse) Connected()        {}
func (connectedFuse) IsConnected() bool { return true }

type registrationPeer struct{}

func (registrationPeer) RegisterConnection(context.Context, pogs.TunnelAuth, uuid.UUID, byte, *pogs.ConnectionOptions) (*pogs.ConnectionDetails, error) {
	return &pogs.ConnectionDetails{UUID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), Location: "LOOP", TunnelIsRemotelyManaged: true}, nil
}
func (registrationPeer) UnregisterConnection(context.Context)                   {}
func (registrationPeer) UpdateLocalConfiguration(context.Context, []byte) error { return nil }

type forwardingOrigin struct{}

func (forwardingOrigin) ProxyHTTP(w connection.ResponseWriter, req *tracing.TracedHTTPRequest, websocket bool) error {
	if req.URL.Path != "/after-control-fin" || websocket {
		return fmt.Errorf("unexpected forwarding request")
	}
	if err := w.WriteRespHeaders(http.StatusOK, http.Header{}); err != nil {
		return err
	}
	_, err := w.Write([]byte("outer-transport-alive"))
	return err
}
func (forwardingOrigin) ProxyTCP(context.Context, connection.ReadWriteAcker, *connection.TCPRequest) error {
	return fmt.Errorf("unused")
}

type forwardingOrchestrator struct{}

func (forwardingOrchestrator) GetOriginProxy() (connection.OriginProxy, error) {
	return forwardingOrigin{}, nil
}
func (forwardingOrchestrator) GetConfigJSON() ([]byte, error) { return nil, fmt.Errorf("unused") }
func (forwardingOrchestrator) UpdateConfig(version int32, _ []byte) *pogs.UpdateConfigurationResponse {
	return &pogs.UpdateConfigurationResponse{LastAppliedVersion: version}
}

type lifetimeDatagrams struct{}

func (lifetimeDatagrams) Serve(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (lifetimeDatagrams) RegisterUdpSession(context.Context, uuid.UUID, net.IP, uint16, time.Duration, string) (*pogs.RegisterUdpSessionResponse, error) {
	return nil, fmt.Errorf("unused")
}
func (lifetimeDatagrams) UnregisterUdpSession(context.Context, uuid.UUID, string) error {
	return fmt.Errorf("unused")
}
func setupControl(t *testing.T, ctx context.Context, protocol connection.Protocol) (connection.ControlStreamHandler, *connection.Observer, *eventTracker, <-chan struct{}) {
	t.Helper()
	log := zerolog.Nop()
	observer := connection.NewObserver(&log)
	tracker := &eventTracker{tunnelstate.NewConnTracker(&log), make(chan connection.Event, 16)}
	observer.RegisterSink(tracker)
	// The source sink channel has capacity 16. Filling it after the tracker
	// makes the final send wait until that first sink has been received.
	for range 16 {
		observer.RegisterSink(connection.EventSinkFunc(func(connection.Event) {}))
	}
	observer.SendURL("https://synthetic.invalid")
	waitEvent(t, ctx, tracker.events, connection.SetURL)
	eof := make(chan struct{})
	control := connection.NewControlStream(observer, connectedFuse{}, &connection.TunnelProperties{}, 0, net.ParseIP("127.0.0.1"),
		func(ctx context.Context, stream io.ReadWriteCloser, timeout time.Duration) tunnelrpc.RegistrationClient {
			return tunnelrpc.NewRegistrationClient(ctx, &eofIO{ReadWriteCloser: stream, eof: eof}, timeout)
		}, time.Second, nil, 0, protocol)
	return control, observer, tracker, eof
}

func TestPinnedGoQUICControlFINLifetime(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	control, observer, tracker, controlEOF := setupControl(t, ctx, connection.QUIC)
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certServer.TLS.Certificates
	certServer.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: certificates, NextProtos: []string{"argotunnel"}}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	defer listener.Close()
	dialed, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"argotunnel"}}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	peer, err := listener.Accept(ctx)
	require.NoError(t, err)
	wrapped, err := cfdquic.NewQUICConnection(dialed, io.NopCloser(bytes.NewReader(nil)))
	require.NoError(t, err)
	log := zerolog.Nop()
	tunnel := connection.NewTunnelConnection(ctx, wrapped, 0, forwardingOrchestrator{}, lifetimeDatagrams{}, control, &client.ConnectionOptionsSnapshot{}, time.Second, time.Second, 0, &log)
	done := make(chan error, 1)
	go func() { done <- tunnel.Serve(ctx) }()
	stream, err := peer.AcceptStream(ctx)
	require.NoError(t, err)
	rpcDone := make(chan error, 1)
	go func() { rpcDone <- tunnelrpc.NewRegistrationServer(registrationPeer{}).Serve(ctx, stream) }()
	waitEvent(t, ctx, tracker.events, connection.Connected)
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	require.NoError(t, stream.Close())
	select {
	case <-controlEOF:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requestStream, err := peer.OpenStreamSync(ctx)
	require.NoError(t, err)
	request := rpcquic.RequestClientStream{ReadWriteCloser: requestStream}
	require.NoError(t, request.WriteConnectRequestData("/after-control-fin", pogs.ConnectionTypeHTTP, pogs.Metadata{Key: "HttpHost", Val: "synthetic.invalid"}, pogs.Metadata{Key: "HttpMethod", Val: "GET"}))
	require.NoError(t, requestStream.Close())
	response, err := request.ReadConnectResponseData()
	require.NoError(t, err)
	require.Empty(t, response.Error)
	body, err := io.ReadAll(requestStream)
	require.NoError(t, err)
	require.Equal(t, "outer-transport-alive", string(body))
	callbackStream, err := peer.OpenStreamSync(ctx)
	require.NoError(t, err)
	callback, err := rpcquic.NewCloudflaredClient(ctx, callbackStream, time.Second)
	require.NoError(t, err)
	configuration, err := callback.UpdateConfiguration(ctx, 19, []byte(`{"synthetic":true}`))
	require.NoError(t, err)
	require.EqualValues(t, 19, configuration.LastAppliedVersion)
	callback.Close()
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	require.True(t, tracker.tracker.HasConnectedWith(connection.QUIC))
	select {
	case err := <-done:
		t.Fatalf("outer QUIC exited after clean control FIN: %v", err)
	default:
	}
	require.NoError(t, peer.CloseWithError(0, "whole transport close"))
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	observer.SendDisconnect(0)
	waitEvent(t, ctx, tracker.events, connection.Disconnected)
	require.Zero(t, tracker.tracker.CountActiveConns())
	require.True(t, tracker.tracker.HasConnectedWith(connection.QUIC))
	select {
	case <-rpcDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Log("decoded ACK -> actual clean control EOF -> HTTP/readiness 1 -> whole QUIC close -> readiness 0/history retained")
}

type edgeH2RPC struct {
	io.Reader
	io.Writer
	response io.Closer
}

func (s edgeH2RPC) Close() error { return s.response.Close() }

type recordedH2Conn struct {
	net.Conn
	mu     sync.Mutex
	writes bytes.Buffer
}

func (c *recordedH2Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.writes.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordedH2Conn) sawCancelReset(t *testing.T) bool {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	wire := c.writes.Bytes()
	require.True(t, bytes.HasPrefix(wire, []byte(http2.ClientPreface)))
	frames := http2.NewFramer(nil, bytes.NewReader(wire[len(http2.ClientPreface):]))
	for {
		frame, err := frames.ReadFrame()
		if err == io.EOF {
			return false
		}
		require.NoError(t, err)
		if reset, ok := frame.(*http2.RSTStreamFrame); ok && reset.StreamID == 1 && reset.ErrCode == http2.ErrCodeCancel {
			return true
		}
	}
}

func TestPinnedGoH2ControlFINAndRSTLifetime(t *testing.T) {
	for _, mode := range []struct{ reset, lateReset bool }{{false, false}, {true, false}, {false, true}} {
		reset, lateReset := mode.reset, mode.lateReset
		t.Run(fmt.Sprintf("reset=%t,late=%t", reset, lateReset), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			control, observer, tracker, controlEOF := setupControl(t, ctx, connection.HTTP2)
			serverSocket, edgeSocket := net.Pipe()
			defer edgeSocket.Close()
			log := zerolog.Nop()
			tunnel := connection.NewHTTP2Connection(serverSocket, forwardingOrchestrator{}, &client.ConnectionOptionsSnapshot{}, observer, 0, control, &log)
			done := make(chan error, 1)
			go func() { done <- tunnel.Serve(ctx) }()
			wire := &recordedH2Conn{Conn: edgeSocket}
			peer, err := (&http2.Transport{}).NewClientConn(wire)
			require.NoError(t, err)
			controlCtx, cancelControl := context.WithCancel(ctx)
			defer cancelControl()
			reader, writer := io.Pipe()
			defer writer.Close()
			request, err := http.NewRequestWithContext(controlCtx, http.MethodPost, "http://synthetic.invalid/control", reader)
			require.NoError(t, err)
			request.Header.Set(connection.InternalUpgradeHeader, connection.ControlStreamUpgrade)
			response, err := peer.RoundTrip(request)
			require.NoError(t, err)
			rpcDone := make(chan error, 1)
			go func() {
				rpcDone <- tunnelrpc.NewRegistrationServer(registrationPeer{}).Serve(ctx, edgeH2RPC{response.Body, writer, response.Body})
			}()
			waitEvent(t, ctx, tracker.events, connection.Connected)
			if reset {
				cancelControl()
				require.NoError(t, writer.CloseWithError(context.Canceled))
				waitEvent(t, ctx, tracker.events, connection.Unregistering)
				require.Zero(t, tracker.tracker.CountActiveConns())
			} else {
				require.NoError(t, writer.Close())
				select {
				case <-controlEOF:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
			}
			configurationRequest, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://synthetic.invalid/configuration", bytes.NewBufferString(`{"version":19,"config":{"synthetic":true}}`))
			require.NoError(t, err)
			configurationRequest.Header.Set(connection.InternalUpgradeHeader, connection.ConfigurationUpdate)
			configurationResponse, err := peer.RoundTrip(configurationRequest)
			require.NoError(t, err)
			configurationBody, err := io.ReadAll(configurationResponse.Body)
			require.NoError(t, err)
			require.NoError(t, configurationResponse.Body.Close())
			require.JSONEq(t, `{"lastAppliedVersion":19,"err":null}`, string(configurationBody))
			forward, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://synthetic.invalid/after-control-fin", nil)
			require.NoError(t, err)
			forwardResponse, err := peer.RoundTrip(forward)
			require.NoError(t, err)
			body, err := io.ReadAll(forwardResponse.Body)
			require.NoError(t, err)
			require.NoError(t, forwardResponse.Body.Close())
			require.Equal(t, "outer-transport-alive", string(body))
			if reset {
				require.True(t, wire.sawCancelReset(t))
			} else {
				require.False(t, wire.sawCancelReset(t))
			}
			if lateReset {
				cancelControl()
				waitEvent(t, ctx, tracker.events, connection.Unregistering)
				require.Zero(t, tracker.tracker.CountActiveConns())
				forwardResponse, err := peer.RoundTrip(forward)
				require.NoError(t, err)
				body, err := io.ReadAll(forwardResponse.Body)
				require.NoError(t, err)
				require.NoError(t, forwardResponse.Body.Close())
				require.Equal(t, "outer-transport-alive", string(body))
				require.True(t, wire.sawCancelReset(t))
			}
			select {
			case err := <-done:
				t.Fatalf("outer H2 exited after control-only end: %v", err)
			default:
			}
			require.NoError(t, edgeSocket.Close())
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !reset && !lateReset {
				waitEvent(t, ctx, tracker.events, connection.Unregistering)
			}
			observer.SendDisconnect(0)
			waitEvent(t, ctx, tracker.events, connection.Disconnected)
			require.Zero(t, tracker.tracker.CountActiveConns())
			require.True(t, tracker.tracker.HasConnectedWith(connection.HTTP2))
			select {
			case <-rpcDone:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			t.Logf("decoded ACK -> control reset=%t -> HTTP remains live -> whole H2 close cleanup", reset)
		})
	}
}
