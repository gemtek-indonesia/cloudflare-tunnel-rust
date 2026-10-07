package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/flow"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	rpcquic "github.com/cloudflare/cloudflared/tunnelrpc/quic"
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type trackedV2Dialer struct {
	ingress.OriginUDPDialer
	created chan net.Conn
}

func (d trackedV2Dialer) DialUDP(address netip.AddrPort) (net.Conn, error) {
	conn, err := d.OriginUDPDialer.DialUDP(address)
	if err == nil {
		d.created <- conn
	}
	return conn, err
}

type trackedV2Limiter struct {
	flow.Limiter
	active   atomic.Int32
	released chan struct{}
}

func (l *trackedV2Limiter) Acquire(kind string) error {
	if err := l.Limiter.Acquire(kind); err != nil {
		return err
	}
	l.active.Add(1)
	return nil
}
func (l *trackedV2Limiter) Release() { l.Limiter.Release(); l.active.Add(-1); l.released <- struct{}{} }

type v2CloseCall struct {
	id     uuid.UUID
	reason string
}
type v2ClosePeer struct {
	calls chan v2CloseCall
	hold  bool
}

func (p v2ClosePeer) RegisterUdpSession(context.Context, uuid.UUID, net.IP, uint16, time.Duration, string) (*pogs.RegisterUdpSessionResponse, error) {
	return nil, fmt.Errorf("unexpected incoming registration on edge")
}
func (p v2ClosePeer) UnregisterUdpSession(ctx context.Context, id uuid.UUID, reason string) error {
	p.calls <- v2CloseCall{id, reason}
	if p.hold {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func sourceV2Pair(t *testing.T, limit uint64) (context.Context, *datagramV2Connection, *quic.Conn, *trackedV2Limiter, chan net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	listener, err := quic.Listen(socket, &tls.Config{Certificates: certificate, NextProtos: []string{"argotunnel"}}, testQUICConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *quic.Conn, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err == nil {
			accepted <- conn
		}
	}()
	clientSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSocket.Close() })
	transport := &quic.Transport{Conn: clientSocket}
	t.Cleanup(func() { _ = transport.Close() })
	conn, err := transport.Dial(ctx, socket.LocalAddr(), &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"argotunnel"}}, testQUICConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "done") })
	control, err := conn.OpenStream()
	require.NoError(t, err)
	require.EqualValues(t, 0, control.StreamID())
	t.Cleanup(func() { _ = control.Close() })
	tracked := &trackedV2Limiter{Limiter: flow.NewLimiter(limit), released: make(chan struct{}, 8)}
	created := make(chan net.Conn, 4)
	log := zerolog.Nop()
	dialer := trackedV2Dialer{ingress.NewDialer(ingress.WarpRoutingConfig{}), created}
	session := NewDatagramV2Connection(ctx, conn, dialer, nil, 0, 100*time.Millisecond, 100*time.Millisecond, tracked, &log).(*datagramV2Connection)
	go func() { _ = session.Serve(ctx) }()
	select {
	case edge := <-accepted:
		t.Cleanup(func() { _ = edge.CloseWithError(0, "done") })
		return ctx, session, edge, tracked, created
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil, nil, nil, nil, nil
	}
}

func acceptV2Close(t *testing.T, ctx context.Context, edge *quic.Conn, peer v2ClosePeer) {
	t.Helper()
	stream, err := edge.AcceptStream(ctx)
	require.NoError(t, err)
	if stream.StreamID() == 0 {
		stream, err = edge.AcceptStream(ctx)
		require.NoError(t, err)
	}
	require.GreaterOrEqual(t, int64(stream.StreamID()), int64(4))
	go func() {
		server := rpcquic.NewCloudflaredServer(func(context.Context, *rpcquic.RequestServerStream) error { return fmt.Errorf("unexpected data") }, peer, nil, time.Second)
		_ = server.Serve(ctx, stream)
	}()
}
func waitV2Release(t *testing.T, ctx context.Context, limiter *trackedV2Limiter) {
	t.Helper()
	select {
	case <-limiter.released:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPinnedGoV2OldSocketClosureUnregistersReplacement(t *testing.T) {
	ctx, session, edge, limiter, created := sourceV2Pair(t, 0)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	destination := origin.LocalAddr().(*net.UDPAddr)
	id := uuid.New()
	_, err = session.RegisterUdpSession(ctx, id, destination.IP, uint16(destination.Port), time.Second, "")
	require.NoError(t, err)
	old := <-created
	_, err = session.RegisterUdpSession(ctx, id, destination.IP, uint16(destination.Port), time.Second, "")
	require.NoError(t, err)
	replacement := <-created
	require.EqualValues(t, 2, limiter.active.Load())
	calls := make(chan v2CloseCall, 4)
	accepted := make(chan struct{})
	go func() {
		acceptV2Close(t, ctx, edge, v2ClosePeer{calls: calls})
		close(accepted)
		acceptV2Close(t, ctx, edge, v2ClosePeer{calls: calls})
	}()
	require.NoError(t, old.Close())
	select {
	case call := <-calls:
		require.Equal(t, id, call.id)
		require.Contains(t, call.reason, "use of closed network connection")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	<-accepted
	waitV2Release(t, ctx, limiter)
	waitV2Release(t, ctx, limiter)
	require.Zero(t, limiter.active.Load())
	_, err = replacement.Write([]byte("replacement must have been closed"))
	require.ErrorIs(t, err, net.ErrClosed)
	t.Log("repeated UUID registration leaves a prior actor live; its socket failure removes and closes the newer session")
}

func TestPinnedGoV2StalledOutgoingRPCOwnsSlotUntilTimeout(t *testing.T) {
	ctx, session, edge, limiter, created := sourceV2Pair(t, 1)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	destination := origin.LocalAddr().(*net.UDPAddr)
	id := uuid.New()
	_, err = session.RegisterUdpSession(ctx, id, destination.IP, uint16(destination.Port), 80*time.Millisecond, "")
	require.NoError(t, err)
	connectedOrigin := <-created
	sourceAddress := connectedOrigin.LocalAddr().(*net.UDPAddr)
	calls := make(chan v2CloseCall, 1)
	go acceptV2Close(t, ctx, edge, v2ClosePeer{calls: calls, hold: true})
	select {
	case call := <-calls:
		require.Equal(t, id, call.id)
		require.Equal(t, "session idle for 80ms", call.reason)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	freed, err := net.ListenUDP("udp", sourceAddress)
	require.NoError(t, err, "origin socket must close before outgoing unregister response")
	require.NoError(t, freed.Close())
	require.EqualValues(t, 1, limiter.active.Load())
	_, err = session.RegisterUdpSession(ctx, uuid.New(), destination.IP, uint16(destination.Port), time.Second, "")
	require.ErrorIs(t, err, flow.ErrTooManyActiveFlows)
	waitV2Release(t, ctx, limiter)
	require.Zero(t, limiter.active.Load())
}
