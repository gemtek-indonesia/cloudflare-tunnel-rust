package connection

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	v3 "github.com/cloudflare/cloudflared/quic/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type v3OriginWriteGate struct {
	*net.UDPConn
	entered, release, closed chan struct{}
	first, closeOnce         sync.Once
	writes                   chan []byte
	outcome                  string
}

func (g *v3OriginWriteGate) Write(payload []byte) (int, error) {
	first := false
	g.first.Do(func() { first = true; close(g.entered) })
	if first {
		select {
		case <-g.release:
		case <-g.closed:
			return 0, net.ErrClosed
		}
		switch g.outcome {
		case "deadline":
			return 0, os.ErrDeadlineExceeded
		case "short":
			return len(payload) - 1, nil
		case "error":
			return 0, errors.New("synthetic origin write failure")
		}
	}
	n, err := g.UDPConn.Write(payload)
	if err == nil {
		g.writes <- append([]byte(nil), payload...)
	}
	return n, err
}

func (g *v3OriginWriteGate) Close() error {
	var err error
	g.closeOnce.Do(func() { close(g.closed); err = g.UDPConn.Close() })
	return err
}

type v3PayloadSendGate struct {
	*quic.Conn
	entered, release, exited chan struct{}
	first                    sync.Once
}

func (g *v3PayloadSendGate) SendDatagram(data []byte) error {
	first := false
	if len(data) > 0 && data[0] == 1 {
		g.first.Do(func() { first = true; close(g.entered) })
	}
	if first {
		defer close(g.exited)
		select {
		case <-g.release:
		case <-g.Context().Done():
			return g.Context().Err()
		}
	}
	return g.Conn.SendDatagram(data)
}

func gatedV3Origin(t *testing.T) (*net.UDPConn, *v3OriginWriteGate) {
	t.Helper()
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	client, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, origin.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	gate := &v3OriginWriteGate{UDPConn: client, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), writes: make(chan []byte, 600)}
	t.Cleanup(func() { _ = gate.Close() })
	return origin, gate
}

func serveGatedV3Session(t *testing.T, f *v3AckFixture, origin io.ReadWriteCloser, idle time.Duration, eyeball v3.DatagramConn, ctx context.Context) (v3.Session, chan error) {
	t.Helper()
	log := zerolog.Nop()
	session := v3.NewSession(v3ID(t, 20), idle, origin, nil, nil, eyeball, v3.NewMetrics(prometheus.NewRegistry()), &log)
	t.Cleanup(func() { _ = session.Close() })
	done := make(chan error, 1)
	go func() { done <- session.Serve(ctx) }()
	return session, done
}

func waitV3Boundary(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual I/O boundary was not reached")
	}
}

func receiveV3Payload(t *testing.T, f *v3AckFixture, expected []byte) {
	t.Helper()
	data, err := f.peer.ReceiveDatagram(f.ctx)
	require.NoError(t, err)
	var payload v3.UDPSessionPayloadDatagram
	require.NoError(t, payload.UnmarshalBinary(data))
	require.Equal(t, expected, payload.Payload)
}

func droppedV3(t *testing.T, registry *prometheus.Registry, reason string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "cloudflared_udp_dropped_datagrams" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "reason" && label.GetValue() == reason {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestPinnedGoV3BlockedOriginWritePreservesReadAndIdleProgress(t *testing.T) {
	f := sourceV3AckFixture(t)
	origin, gate := gatedV3Origin(t)
	log := zerolog.Nop()
	eyeball := v3.NewDatagramConn(f.conn, nil, nil, 0, v3.NewMetrics(prometheus.NewRegistry()), &log)
	session, done := serveGatedV3Session(t, f, gate, 100*time.Millisecond, eyeball, f.ctx)
	session.Write([]byte("blocked write"))
	waitV3Boundary(t, gate.entered)
	_, err := origin.WriteToUDP([]byte("reader remains independent"), gate.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	receiveV3Payload(t, f, []byte("reader remains independent"))
	select {
	case err := <-done:
		require.EqualError(t, err, "flow was idle for 100ms")
	case <-time.After(time.Second):
		t.Fatal("blocked writer must not block idle closure")
	}
	waitV3Boundary(t, gate.closed)
}

func TestPinnedGoV3BlockedPayloadSendPreservesWriterAndMigration(t *testing.T) {
	old := sourceV3AckFixture(t)
	next := sourceV3AckFixture(t)
	origin, gate := gatedV3Origin(t)
	close(gate.release)
	sendGate := &v3PayloadSendGate{Conn: old.conn.Conn, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	log := zerolog.Nop()
	metrics := v3.NewMetrics(prometheus.NewRegistry())
	eyeball := v3.NewDatagramConn(sendGate, nil, nil, 0, metrics, &log)
	ctx, cancel := context.WithCancel(old.conn.Context())
	defer cancel()
	session, done := serveGatedV3Session(t, old, gate, time.Second, eyeball, ctx)
	_, err := origin.WriteToUDP([]byte("held old-route reply"), gate.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	waitV3Boundary(t, sendGate.entered)
	session.Write([]byte("writer progresses during send"))
	receiveOrigin(t, origin, []byte("writer progresses during send"))
	migrated := make(chan struct{})
	go func() {
		session.Migrate(v3.NewDatagramConn(next.conn, nil, nil, 1, metrics, &log), next.conn.Context(), &log)
		close(migrated)
	}()
	waitV3Boundary(t, migrated)
	cancel()
	close(sendGate.release)
	receiveV3Payload(t, old, []byte("held old-route reply"))
	_, err = origin.WriteToUDP([]byte("next reply uses migrated route"), gate.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	receiveV3Payload(t, next, []byte("next reply uses migrated route"))
	require.Equal(t, uint8(1), session.ConnectionID())
	require.NoError(t, session.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, v3.SessionCloseErr)
	case <-time.After(time.Second):
		t.Fatal("close did not stop lifecycle")
	}
	waitV3Boundary(t, sendGate.exited)
}

func TestPinnedGoV3BlockedPayloadSendDoesNotBlockIdleOrCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "cancel"}[cancelEarly], func(t *testing.T) {
			f := sourceV3AckFixture(t)
			origin, gate := gatedV3Origin(t)
			sendGate := &v3PayloadSendGate{Conn: f.conn.Conn, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			log := zerolog.Nop()
			eyeball := v3.NewDatagramConn(sendGate, nil, nil, 0, v3.NewMetrics(prometheus.NewRegistry()), &log)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			_, done := serveGatedV3Session(t, f, gate, 100*time.Millisecond, eyeball, ctx)
			_, err := origin.WriteToUDP([]byte("blocked send"), gate.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			waitV3Boundary(t, sendGate.entered)
			if cancelEarly {
				cancel()
			}
			select {
			case err := <-done:
				if cancelEarly {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.EqualError(t, err, "flow was idle for 100ms")
				}
			case <-time.After(time.Second):
				t.Fatal("send boundary must not block lifecycle")
			}
			waitV3Boundary(t, gate.closed)
			require.NoError(t, f.conn.CloseWithError(0, "done"))
			waitV3Boundary(t, sendGate.exited)
		})
	}
}

func TestPinnedGoV3WriterQueueAndDropBoundaries(t *testing.T) {
	f := sourceV3AckFixture(t)
	_, gate := gatedV3Origin(t)
	log := zerolog.Nop()
	registry := prometheus.NewRegistry()
	metrics := v3.NewMetrics(registry)
	eyeball := v3.NewDatagramConn(f.conn, nil, nil, 0, metrics, &log)
	session := v3.NewSession(v3ID(t, 21), time.Second, gate, nil, nil, eyeball, metrics, &log)
	done := make(chan error, 1)
	go func() { done <- session.Serve(f.ctx) }()
	session.Write([]byte{0, 0})
	waitV3Boundary(t, gate.entered)
	for i := 1; i <= 513; i++ {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, uint16(i))
		session.Write(data)
	}
	require.Equal(t, float64(1), droppedV3(t, registry, "write_full"))
	close(gate.release)
	for i := 0; i <= 512; i++ {
		select {
		case data := <-gate.writes:
			require.Equal(t, uint16(i), binary.BigEndian.Uint16(data))
		case <-time.After(time.Second):
			t.Fatal("admitted queued write missing")
		}
	}
	select {
	case data := <-gate.writes:
		t.Fatalf("overflow payload reached socket: %v", data)
	case <-time.After(30 * time.Millisecond):
	}
	require.NoError(t, session.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("queue fixture did not close")
	}
}

func TestPinnedGoV3WriterDeadlineShortAndFatalOutcomes(t *testing.T) {
	for _, outcome := range []string{"deadline", "short", "error"} {
		t.Run(outcome, func(t *testing.T) {
			f := sourceV3AckFixture(t)
			origin, gate := gatedV3Origin(t)
			gate.outcome = outcome
			log := zerolog.Nop()
			registry := prometheus.NewRegistry()
			metrics := v3.NewMetrics(registry)
			eyeball := v3.NewDatagramConn(f.conn, nil, nil, 0, metrics, &log)
			session := v3.NewSession(v3ID(t, 22), time.Second, gate, nil, nil, eyeball, metrics, &log)
			done := make(chan error, 1)
			go func() { done <- session.Serve(f.ctx) }()
			session.Write([]byte("discard"))
			waitV3Boundary(t, gate.entered)
			session.Write([]byte("next packet"))
			close(gate.release)
			if outcome == "error" {
				select {
				case err := <-done:
					require.EqualError(t, err, "synthetic origin write failure")
				case <-time.After(time.Second):
					t.Fatal("fatal write did not close")
				}
				waitV3Boundary(t, gate.closed)
				return
			}
			receiveOrigin(t, origin, []byte("next packet"))
			reason := "write_failed"
			if outcome == "deadline" {
				reason = "write_deadline_exceeded"
			}
			require.Equal(t, float64(1), droppedV3(t, registry, reason))
			require.NoError(t, session.Close())
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("drop fixture did not close")
			}
		})
	}
}
