package v3

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/packet"
)

type sourceICMPConn struct{ ctx context.Context }

func (c sourceICMPConn) Context() context.Context { return c.ctx }
func (sourceICMPConn) SendDatagram([]byte) error  { return errors.New("synthetic ICMP send failure") }
func (c sourceICMPConn) ReceiveDatagram(context.Context) ([]byte, error) {
	<-c.ctx.Done()
	return nil, c.ctx.Err()
}

type sourceICMPRoute struct {
	entered chan struct{}
	release chan struct{}
}

func (r sourceICMPRoute) Request(ctx context.Context, pk *packet.ICMP, responder ingress.ICMPResponder) error {
	if r.entered != nil {
		select {
		case r.entered <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-r.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return errors.New("synthetic ICMP origin failure")
}
func (sourceICMPRoute) ConvertToTTLExceeded(pk *packet.ICMP, raw packet.RawPacket) *packet.ICMP {
	return packet.NewICMPTTLExceedPacket(pk.IP, raw, netip.MustParseAddr("127.0.0.1"))
}

func sourceICMPDatagram(t *testing.T, ttl uint8) *ICMPDatagram {
	t.Helper()
	pk := &packet.ICMP{
		IP:      &packet.IP{Src: netip.MustParseAddr("127.0.0.1"), Dst: netip.MustParseAddr("127.0.0.1"), Protocol: layers.IPProtocolICMPv4, TTL: ttl},
		Message: &icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 1, Seq: 1}},
	}
	raw, err := packet.NewEncoder().Encode(pk)
	require.NoError(t, err)
	return &ICMPDatagram{Payload: append([]byte(nil), raw.Data...)}
}

func sourceICMPCount(t *testing.T, registry *prometheus.Registry, reason string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() == "cloudflared_icmp_dropped_packets" {
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "reason" && label.GetValue() == reason {
						return metric.GetCounter().GetValue()
					}
				}
			}
		}
	}
	return 0
}

func TestPinnedGoV3ICMPQueueDisabledAndFailureEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		log := zerolog.Nop()
		registry := prometheus.NewRegistry()
		metrics := NewMetrics(registry)
		route := sourceICMPRoute{entered: make(chan struct{}, 1), release: make(chan struct{})}
		c := NewDatagramConn(sourceICMPConn{ctx}, nil, route, 2, metrics, &log).(*datagramConn)
		done := make(chan struct{})
		go func() { c.processICMPDatagrams(ctx); close(done) }()
		c.handleICMPPacket(sourceICMPDatagram(t, 64))
		<-route.entered
		for range 128 {
			c.handleICMPPacket(sourceICMPDatagram(t, 64))
		}
		require.Len(t, c.icmpDatagramChan, 128)
		c.handleICMPPacket(sourceICMPDatagram(t, 64))
		require.Equal(t, float64(1), sourceICMPCount(t, registry, "write_full"))
		cancel()
		close(route.release)
		<-done
		require.GreaterOrEqual(t, sourceICMPCount(t, registry, "write_failed"), float64(1))
		c.icmpRouter = nil
		before := sourceICMPCount(t, registry, "write_full")
		c.handleICMPPacket(&ICMPDatagram{Payload: []byte{0xff}})
		require.Equal(t, before, sourceICMPCount(t, registry, "write_full"))
	})

	log := zerolog.Nop()
	registry := prometheus.NewRegistry()
	c := NewDatagramConn(sourceICMPConn{t.Context()}, nil, sourceICMPRoute{}, 2, NewMetrics(registry), &log).(*datagramConn)
	c.writeICMPPacket(&ICMPDatagram{Payload: []byte{0xff}})
	require.Equal(t, float64(1), sourceICMPCount(t, registry, "write_failed"))
	c.writeICMPPacket(sourceICMPDatagram(t, 64))
	require.Equal(t, float64(2), sourceICMPCount(t, registry, "write_failed"))
	c.writeICMPPacket(sourceICMPDatagram(t, 1))
	require.Equal(t, float64(3), sourceICMPCount(t, registry, "write_failed"))
}
