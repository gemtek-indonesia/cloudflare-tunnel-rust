package connection

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/flow"
	"github.com/cloudflare/cloudflared/ingress"
	v3 "github.com/cloudflare/cloudflared/quic/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type v3ResponseGate struct {
	id      v3.RequestID
	kind    byte
	entered chan struct{}
	release chan struct{}
	fail    bool
	once    sync.Once
}
type v3GatedConn struct {
	*quic.Conn
	mutex sync.Mutex
	gate  *v3ResponseGate
}

func (c *v3GatedConn) SendDatagram(data []byte) error {
	c.mutex.Lock()
	gate := c.gate
	c.mutex.Unlock()
	if gate != nil && len(data) >= 17 && data[0] == gate.kind {
		offset := 1
		if gate.kind == 3 {
			offset = 2
		}
		if len(data) < offset+16 {
			return fmt.Errorf("short gated datagram")
		}
		id, err := v3.RequestIDFromSlice(data[offset : offset+16])
		if err == nil && id == gate.id {
			gate.once.Do(func() { close(gate.entered) })
			select {
			case <-gate.release:
			case <-c.Context().Done():
				return c.Context().Err()
			}
			if gate.fail {
				return fmt.Errorf("synthetic response transport failure")
			}
		}
	}
	return c.Conn.SendDatagram(data)
}
func (c *v3GatedConn) arm(id v3.RequestID, fail bool) *v3ResponseGate {
	return c.armKind(id, 3, fail)
}
func (c *v3GatedConn) armPayload(id v3.RequestID, fail bool) *v3ResponseGate {
	return c.armKind(id, 1, fail)
}
func (c *v3GatedConn) armKind(id v3.RequestID, kind byte, fail bool) *v3ResponseGate {
	gate := &v3ResponseGate{id: id, kind: kind, entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
	c.mutex.Lock()
	c.gate = gate
	c.mutex.Unlock()
	return gate
}

type v3AckFixture struct {
	ctx      context.Context
	conn     *v3GatedConn
	peer     *quic.Conn
	manager  v3.SessionManager
	limiter  *trackedV2Limiter
	registry *prometheus.Registry
	handler  DatagramSessionHandler
}

func sourceV3AckFixture(t *testing.T) *v3AckFixture {
	return sourceV3SharedAckFixture(t, nil, 0)
}
func sourceV3SharedAckFixture(t *testing.T, manager v3.SessionManager, index uint8) *v3AckFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certificateServer.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	serverSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSocket.Close() })
	listener, err := quic.Listen(serverSocket, &tls.Config{Certificates: certificates, NextProtos: []string{"argotunnel"}}, testQUICConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *quic.Conn, 1)
	go func() {
		peer, err := listener.Accept(ctx)
		if err == nil {
			accepted <- peer
		}
	}()
	clientSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSocket.Close() })
	transport := &quic.Transport{Conn: clientSocket}
	t.Cleanup(func() { _ = transport.Close() })
	client, err := transport.Dial(ctx, serverSocket.LocalAddr(), &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"argotunnel"}}, testQUICConfig)
	require.NoError(t, err)
	conn := &v3GatedConn{Conn: client}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "done") })
	log := zerolog.Nop()
	registry := prometheus.NewRegistry()
	metrics := v3.NewMetrics(registry)
	limiter := &trackedV2Limiter{Limiter: flow.NewLimiter(0), released: make(chan struct{}, 8)}
	if manager == nil {
		manager = v3.NewSessionManager(metrics, &log, ingress.NewDialer(ingress.WarpRoutingConfig{}), limiter)
	}
	handler := NewDatagramV3Connection(ctx, conn, manager, nil, index, metrics, &log)
	go func() { _ = handler.Serve(ctx) }()
	select {
	case peer := <-accepted:
		t.Cleanup(func() { _ = peer.CloseWithError(0, "done") })
		return &v3AckFixture{ctx: ctx, conn: conn, peer: peer, manager: manager, limiter: limiter, registry: registry, handler: handler}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil
	}
}

func TestPinnedGoV3CanceledCreatorRetiresPendingMigratedSession(t *testing.T) {
	creator := sourceV3AckFixture(t)
	migrated := sourceV3SharedAckFixture(t, creator.manager, 1)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	id := v3ID(t, 5)
	gate := creator.conn.arm(id, false)
	destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
	sendV3Registration(t, creator, id, destination, 5*time.Second)
	select {
	case <-gate.entered:
	case <-creator.ctx.Done():
		t.Fatal(creator.ctx.Err())
	}
	sendV3Registration(t, migrated, id, destination, 5*time.Second)
	probe, cancel := context.WithTimeout(migrated.ctx, 100*time.Millisecond)
	defer cancel()
	_, err = migrated.peer.ReceiveDatagram(probe)
	require.ErrorIs(t, err, context.DeadlineExceeded, "migration cannot acknowledge before creator starts Serve")
	current, err := creator.manager.GetSession(id)
	require.NoError(t, err)
	require.Equal(t, uint8(1), current.ConnectionID())
	require.NoError(t, creator.conn.CloseWithError(0, "creator canceled before response"))
	select {
	case <-creator.limiter.released:
	case <-time.After(time.Second):
		t.Fatal("creator response failure must unregister the pending session")
	}
	_, err = creator.manager.GetSession(id)
	require.ErrorIs(t, err, v3.ErrSessionNotFound)
	probe, cancelAgain := context.WithTimeout(migrated.ctx, 100*time.Millisecond)
	defer cancelAgain()
	_, err = migrated.peer.ReceiveDatagram(probe)
	require.ErrorIs(t, err, context.DeadlineExceeded, "failed creator must not produce a migration response")
	next := v3ID(t, 7)
	sendV3Registration(t, migrated, next, destination, 5*time.Second)
	receiveV3Response(t, migrated, next)
}
func v3ID(t *testing.T, last byte) v3.RequestID {
	id, err := v3.RequestIDFromSlice(append(make([]byte, 15), last))
	require.NoError(t, err)
	return id
}
func sendV3Registration(t *testing.T, f *v3AckFixture, id v3.RequestID, destination netip.AddrPort, idle time.Duration) {
	data, err := (&v3.UDPSessionRegistrationDatagram{RequestID: id, Dest: destination, IdleDurationHint: idle}).MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, f.peer.SendDatagram(data))
}
func receiveV3Response(t *testing.T, f *v3AckFixture, id v3.RequestID) {
	data, err := f.peer.ReceiveDatagram(f.ctx)
	require.NoError(t, err)
	var response v3.UDPSessionRegistrationResponseDatagram
	require.NoError(t, response.UnmarshalBinary(data))
	require.Equal(t, id, response.RequestID)
	require.Equal(t, v3.ResponseOk, response.ResponseType)
}
func sendV3Payload(t *testing.T, f *v3AckFixture, id v3.RequestID, payload []byte) {
	data := make([]byte, v3.DatagramPayloadHeaderLen+len(payload))
	require.NoError(t, v3.MarshalPayloadHeaderTo(id, data))
	copy(data[v3.DatagramPayloadHeaderLen:], payload)
	require.NoError(t, f.peer.SendDatagram(data))
}
func receiveOrigin(t *testing.T, origin *net.UDPConn, expected []byte) {
	require.NoError(t, origin.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 1500)
	n, _, err := origin.ReadFromUDP(buffer)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, buffer[:n]))
}

func TestPinnedGoV3ResponseGateAndIndependentReceiveProgress(t *testing.T) {
	f := sourceV3AckFixture(t)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
	live := v3ID(t, 1)
	pending := v3ID(t, 2)
	sendV3Registration(t, f, live, destination, 5*time.Second)
	receiveV3Response(t, f, live)
	gate := f.conn.arm(pending, false)
	sendV3Registration(t, f, pending, destination, 5*time.Second)
	select {
	case <-gate.entered:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	sendV3Payload(t, f, pending, []byte("must queue before response"))
	require.NoError(t, origin.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
	_, _, err = origin.ReadFromUDP(make([]byte, 128))
	require.Error(t, err, "new session must not start the writer before response send succeeds")
	sendV3Payload(t, f, live, []byte("existing flow progresses"))
	receiveOrigin(t, origin, []byte("existing flow progresses"))
	close(gate.release)
	receiveV3Response(t, f, pending)
	receiveOrigin(t, origin, []byte("must queue before response"))
}

func TestPinnedGoV3RetryRefreshRequiresSuccessfulResponseSend(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := sourceV3AckFixture(t)
			origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer origin.Close()
			destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
			id := v3ID(t, 3)
			sendV3Registration(t, f, id, destination, time.Second)
			receiveV3Response(t, f, id)
			timer := time.NewTimer(700 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			}
			prior, err := f.manager.GetSession(id)
			require.NoError(t, err)
			gate := f.conn.arm(id, fail)
			sendV3Registration(t, f, id, netip.MustParseAddrPort("127.0.0.1:1"), 20*time.Second)
			select {
			case <-gate.entered:
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			}
			current, err := f.manager.GetSession(id)
			require.NoError(t, err)
			require.Same(t, prior, current)
			if fail {
				select {
				case <-f.limiter.released:
				case <-time.After(600 * time.Millisecond):
					t.Fatal("stalled retry response must not extend prior idle lifetime")
				}
				_, err = f.manager.GetSession(id)
				require.ErrorIs(t, err, v3.ErrSessionNotFound)
				close(gate.release)
			} else {
				close(gate.release)
				receiveV3Response(t, f, id)
				select {
				case <-f.limiter.released:
					t.Fatal("successful retry must refresh the original idle duration")
				case <-time.After(600 * time.Millisecond):
				}
				select {
				case <-f.limiter.released:
				case <-time.After(600 * time.Millisecond):
					t.Fatal("retry must retain the original one-second timeout")
				}
			}
		})
	}
}

func TestPinnedGoV3DuplicateResponseCannotStartBeforeCreator(t *testing.T) {
	f := sourceV3AckFixture(t)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
	id := v3ID(t, 4)
	creator := f.conn.arm(id, true)
	sendV3Registration(t, f, id, destination, 5*time.Second)
	select {
	case <-creator.entered:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	retry := f.conn.arm(id, false)
	sendV3Registration(t, f, id, destination, 5*time.Second)
	select {
	case <-retry.entered:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	close(retry.release)
	receiveV3Response(t, f, id)
	sendV3Payload(t, f, id, []byte("no writer before creator response"))
	require.NoError(t, origin.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, _, err = origin.ReadFromUDP(make([]byte, 128))
	require.Error(t, err)
	close(creator.release)
	select {
	case <-f.limiter.released:
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	_, err = f.manager.GetSession(id)
	require.ErrorIs(t, err, v3.ErrSessionNotFound)
}
