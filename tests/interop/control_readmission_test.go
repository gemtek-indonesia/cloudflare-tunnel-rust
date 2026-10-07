package connection_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/cloudflare/cloudflared/tunnelstate"
)

type observedControl struct {
	connection.ControlStreamHandler
	returned chan error
}

func (c *observedControl) ServeControlStream(ctx context.Context, stream io.ReadWriteCloser, options *pogs.ConnectionOptions, config connection.TunnelConfigJSONGetter) error {
	err := c.ControlStreamHandler.ServeControlStream(ctx, stream, options, config)
	c.returned <- err
	return err
}

type preAckPeer struct {
	registrationPeer
	mode    string
	entered chan struct{}
}

func (s preAckPeer) RegisterConnection(ctx context.Context, _ pogs.TunnelAuth, _ uuid.UUID, _ byte, _ *pogs.ConnectionOptions) (*pogs.ConnectionDetails, error) {
	close(s.entered)
	switch s.mode {
	case "reject":
		return nil, errors.New("synthetic registration rejection")
	case "retryable":
		return nil, pogs.RetryErrorAfter(errors.New("synthetic retryable rejection"), 99*time.Second)
	case "cancel":
		<-ctx.Done()
		return nil, ctx.Err()
	default:
		panic("invalid fixture mode")
	}
}

type peerControlAttempt struct {
	cancel  context.CancelFunc
	writer  *io.PipeWriter
	rpcDone <-chan error
}

type retainedPeerRPC struct {
	io.Reader
	io.Writer
}

func (retainedPeerRPC) Close() error { return nil }

type recordedReadmissionConn struct {
	*recordedH2Conn
	mu        sync.Mutex
	responses bytes.Buffer
	changed   chan struct{}
}

func (c *recordedReadmissionConn) Read(p []byte) (int, error) {
	n, err := c.recordedH2Conn.Read(p)
	c.mu.Lock()
	c.responses.Write(p[:n])
	c.mu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (c *recordedReadmissionConn) termination(stream uint32) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := http2.NewFramer(nil, bytes.NewReader(c.responses.Bytes()))
	for {
		frame, err := frames.ReadFrame()
		if err != nil {
			return "", false
		}
		if frame.Header().StreamID != stream {
			continue
		}
		switch frame := frame.(type) {
		case *http2.RSTStreamFrame:
			return fmt.Sprintf("RST_STREAM %s", frame.ErrCode), true
		case *http2.DataFrame:
			if frame.StreamEnded() {
				return "END_STREAM", true
			}
		case *http2.HeadersFrame:
			if frame.StreamEnded() {
				return "END_STREAM", true
			}
		}
	}
}
func (c *recordedReadmissionConn) waitTermination(t *testing.T, ctx context.Context, stream uint32) string {
	t.Helper()
	for {
		if termination, ok := c.termination(stream); ok {
			return termination
		}
		select {
		case <-c.changed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
			return ""
		}
	}
}

func startControlAttempt(t *testing.T, ctx context.Context, peer *http2.ClientConn, implementation pogs.RegistrationServer) peerControlAttempt {
	t.Helper()
	requestContext, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "http://synthetic.invalid/control", reader)
	require.NoError(t, err)
	request.Header.Set(connection.InternalUpgradeHeader, connection.ControlStreamUpgrade)
	response, err := peer.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	done := make(chan error, 1)
	go func() {
		done <- tunnelrpc.NewRegistrationServer(implementation).Serve(ctx, retainedPeerRPC{response.Body, writer})
	}()
	return peerControlAttempt{cancel, writer, done}
}

func (a peerControlAttempt) reset(t *testing.T) {
	t.Helper()
	a.cancel()
	require.NoError(t, a.writer.CloseWithError(context.Canceled))
}

func waitError(t *testing.T, ctx context.Context, returned <-chan error) error {
	t.Helper()
	select {
	case err := <-returned:
		return err
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil
	}
}

func assertOuterForwarding(t *testing.T, ctx context.Context, peer *http2.ClientConn, done <-chan error) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://synthetic.invalid/after-control-fin", nil)
	require.NoError(t, err)
	response, err := peer.RoundTrip(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "outer-transport-alive", string(body))
	request, err = http.NewRequestWithContext(ctx, http.MethodPut, "http://synthetic.invalid/configuration", bytes.NewBufferString(`{"version":21,"config":{"synthetic":true}}`))
	require.NoError(t, err)
	request.Header.Set(connection.InternalUpgradeHeader, connection.ConfigurationUpdate)
	response, err = peer.RoundTrip(request)
	require.NoError(t, err)
	body, err = io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.JSONEq(t, `{"lastAppliedVersion":21,"err":null}`, string(body))
	select {
	case err := <-done:
		t.Fatalf("outer H2 ended before peer closure: %v", err)
	default:
	}
}

func newReadmissionConnection(t *testing.T, ctx context.Context, graceful <-chan struct{}) (*http2.ClientConn, *recordedReadmissionConn, *observedControl, *eventTracker, <-chan error) {
	t.Helper()
	log := zerolog.Nop()
	observer := connection.NewObserver(&log)
	tracker := &eventTracker{tunnelstate.NewConnTracker(&log), make(chan connection.Event, 16)}
	observer.RegisterSink(tracker)
	for range 16 {
		observer.RegisterSink(connection.EventSinkFunc(func(connection.Event) {}))
	}
	observer.SendURL("https://synthetic.invalid")
	waitEvent(t, ctx, tracker.events, connection.SetURL)
	base := connection.NewControlStream(observer, connectedFuse{}, &connection.TunnelProperties{}, 0, net.ParseIP("127.0.0.1"), nil, 3*time.Second, graceful, time.Second, connection.HTTP2)
	control := &observedControl{base, make(chan error, 8)}
	serverSocket, edgeSocket := net.Pipe()
	tunnel := connection.NewHTTP2Connection(serverSocket, forwardingOrchestrator{}, &client.ConnectionOptionsSnapshot{}, observer, 0, control, &log)
	done := make(chan error, 1)
	go func() { done <- tunnel.Serve(ctx) }()
	wire := &recordedReadmissionConn{recordedH2Conn: &recordedH2Conn{Conn: edgeSocket}, changed: make(chan struct{}, 1)}
	peer, err := (&http2.Transport{}).NewClientConn(wire)
	require.NoError(t, err)
	return peer, wire, control, tracker, done
}

func TestPinnedGoH2PreAckFailureAndReadmission(t *testing.T) {
	for _, mode := range []string{"reject", "retryable", "cancel"} {
		for _, readmit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/readmit=%t", mode, readmit), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				peer, socket, control, tracker, done := newReadmissionConnection(t, ctx, nil)
				defer socket.Close()
				entered := make(chan struct{})
				first := startControlAttempt(t, ctx, peer, preAckPeer{mode: mode, entered: entered})
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if mode == "cancel" {
					first.reset(t)
				}
				failure := waitError(t, ctx, control.returned)
				var registration connection.ServerRegisterTunnelError
				require.ErrorAs(t, failure, &registration)
				require.Equal(t, mode != "retryable", registration.Permanent)
				if mode == "cancel" {
					require.True(t, socket.sawCancelReset(t))
				}
				_ = waitError(t, ctx, first.rpcDone)
				if mode != "cancel" {
					require.Equal(t, "END_STREAM", socket.waitTermination(t, ctx, 1))
				}
				require.Zero(t, tracker.tracker.CountActiveConns())
				require.False(t, tracker.tracker.HasConnectedWith(connection.HTTP2))
				assertOuterForwarding(t, ctx, peer, done)
				lastFailure := failure
				if readmit {
					second := startControlAttempt(t, ctx, peer, registrationPeer{})
					waitEvent(t, ctx, tracker.events, connection.Connected)
					require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
					assertOuterForwarding(t, ctx, peer, done)
					second.reset(t)
					waitEvent(t, ctx, tracker.events, connection.Unregistering)
					lastFailure = waitError(t, ctx, control.returned)
					require.True(t, strings.HasPrefix(lastFailure.Error(), "Error shutting down control stream:"), lastFailure.Error())
					_ = waitError(t, ctx, second.rpcDone)
					require.Zero(t, tracker.tracker.CountActiveConns())
					assertOuterForwarding(t, ctx, peer, done)
				}
				require.NoError(t, socket.Close())
				outerFailure := waitError(t, ctx, done)
				require.EqualError(t, outerFailure, lastFailure.Error())
				t.Logf("pre-ACK %s permanent=%t; later control accepted=%t; outer returned latest completed control failure %T: %v", mode, registration.Permanent, readmit, outerFailure, outerFailure)
			})
		}
	}
}

type gracefulPeer struct {
	registrationPeer
	id           string
	unregistered chan string
}

func (s gracefulPeer) UnregisterConnection(context.Context) { s.unregistered <- s.id }

func TestPinnedGoH2GracefulUnregistersEveryAdmittedControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	graceful := make(chan struct{})
	peer, socket, control, tracker, done := newReadmissionConnection(t, ctx, graceful)
	defer socket.Close()
	unregistered := make(chan string, 2)
	first := startControlAttempt(t, ctx, peer, gracefulPeer{id: "first", unregistered: unregistered})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	second := startControlAttempt(t, ctx, peer, gracefulPeer{id: "second", unregistered: unregistered})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	close(graceful)
	ids := make(map[string]bool)
	for range 2 {
		select {
		case id := <-unregistered:
			ids[id] = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	require.Equal(t, map[string]bool{"first": true, "second": true}, ids)
	for range 2 {
		require.NoError(t, waitError(t, ctx, control.returned))
	}
	for range 2 {
		waitEvent(t, ctx, tracker.events, connection.Unregistering)
	}
	require.Zero(t, tracker.tracker.CountActiveConns())
	require.Equal(t, "END_STREAM", socket.waitTermination(t, ctx, 1))
	require.Equal(t, "END_STREAM", socket.waitTermination(t, ctx, 3))
	_ = waitError(t, ctx, first.rpcDone)
	_ = waitError(t, ctx, second.rpcDone)
	assertOuterForwarding(t, ctx, peer, done)
	require.NoError(t, socket.Close())
	require.NoError(t, waitError(t, ctx, done))
	t.Log("every admitted control received actual graceful unregister and response FIN; outer stayed usable until peer closed and then returned nil")
}

func TestPinnedGoH2ReadmissionAfterAdmittedReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peer, socket, control, tracker, done := newReadmissionConnection(t, ctx, nil)
	defer socket.Close()
	first := startControlAttempt(t, ctx, peer, registrationPeer{})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	first.reset(t)
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	_ = waitError(t, ctx, control.returned)
	_ = waitError(t, ctx, first.rpcDone)
	require.Zero(t, tracker.tracker.CountActiveConns())
	second := startControlAttempt(t, ctx, peer, registrationPeer{})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	require.True(t, tracker.tracker.HasConnectedWith(connection.HTTP2))
	assertOuterForwarding(t, ctx, peer, done)
	second.reset(t)
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	lastFailure := waitError(t, ctx, control.returned)
	require.True(t, strings.HasPrefix(lastFailure.Error(), "Error shutting down control stream:"), lastFailure.Error())
	_ = waitError(t, ctx, second.rpcDone)
	require.Zero(t, tracker.tracker.CountActiveConns())
	require.NoError(t, socket.Close())
	outerFailure := waitError(t, ctx, done)
	require.EqualError(t, outerFailure, lastFailure.Error())
	t.Logf("second control re-registered after prior admitted reset; outer returned %T: %v", outerFailure, outerFailure)
}

func TestPinnedGoH2AcceptsSecondControlWhileFirstAdmissionActive(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	peer, socket, control, tracker, done := newReadmissionConnection(t, ctx, nil)
	defer socket.Close()
	first := startControlAttempt(t, ctx, peer, registrationPeer{})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	second := startControlAttempt(t, ctx, peer, registrationPeer{})
	waitEvent(t, ctx, tracker.events, connection.Connected)
	require.EqualValues(t, 1, tracker.tracker.CountActiveConns())
	assertOuterForwarding(t, ctx, peer, done)
	first.reset(t)
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	_ = waitError(t, ctx, control.returned)
	_ = waitError(t, ctx, first.rpcDone)
	require.Zero(t, tracker.tracker.CountActiveConns(), "source Unregistering clears the index even while another admitted control is active")
	assertOuterForwarding(t, ctx, peer, done)
	select {
	case err := <-second.rpcDone:
		t.Fatalf("second control ended when first control reset: %v", err)
	default:
	}
	second.reset(t)
	waitEvent(t, ctx, tracker.events, connection.Unregistering)
	lastFailure := waitError(t, ctx, control.returned)
	_ = waitError(t, ctx, second.rpcDone)
	require.NoError(t, socket.Close())
	require.EqualError(t, waitError(t, ctx, done), lastFailure.Error())
	t.Log("second control admitted while first remained active; resetting first clears source index readiness despite second control/outer forwarding remaining live")
}
