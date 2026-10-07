//go:build linux

package ingress

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"google.golang.org/protobuf/proto"

	"github.com/cloudflare/cloudflared/packet"
	"github.com/cloudflare/cloudflared/tracing"
)

func TestPinnedGoICMPStartupFamilyAvailabilityAndPermission(t *testing.T) {
	log := zerolog.Nop()
	bad4 := netip.MustParseAddr("192.0.2.254")
	bad6 := netip.MustParseAddr("2001:db8::ffff")
	router, err := NewICMPRouter(bad4, bad6, &log, time.Second)
	require.Error(t, err)
	require.Nil(t, router)
	for _, family := range []struct {
		v4, v6 netip.Addr
		ipv4   bool
	}{
		{netip.MustParseAddr("127.0.0.1"), bad6, true},
		{bad4, netip.MustParseAddr("::1"), false},
	} {
		router, err := NewICMPRouter(family.v4, family.v6, &log, time.Second)
		if err != nil {
			t.Logf("unprivileged family unavailable: %v", err)
			continue
		}
		actual := router.(*icmpRouter)
		require.Equal(t, family.ipv4, actual.ipv4Proxy != nil)
		require.Equal(t, !family.ipv4, actual.ipv6Proxy != nil)
	}
	raw, err := os.ReadFile(pingGroupPath)
	if err == nil {
		bounds := findGroupIDRegex.FindAll(raw, 2)
		if len(bounds) == 2 {
			low, lowErr := strconv.ParseUint(string(bounds[0]), 10, 32)
			high, highErr := strconv.ParseUint(string(bounds[1]), 10, 32)
			if lowErr == nil && highErr == nil {
				gid := uint64(os.Getegid())
				require.Equal(t, gid >= low && gid <= high, checkInPingGroup() == nil)
			}
		}
	}
}

func TestPinnedGoICMPEarlyEchoAndBindFailureExportRequestSpan(t *testing.T) {
	for _, echo := range []bool{false, true} {
		log := zerolog.Nop()
		muxer := newMockMuxer(1)
		responder := newPacketResponder(muxer, 2, packet.NewEncoder())
		traced := tracing.NewTracedContext(context.Background(), "11111111111111111111111111111111:2222222222222222:0:1", &log)
		responder.AddTraceContext(traced, make([]byte, 25))
		message := &icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: []byte{1}}}
		if echo {
			message = &icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 7, Seq: 3}}
		}
		pk := &packet.ICMP{IP: &packet.IP{Src: netip.MustParseAddr("127.0.0.1"), Dst: netip.MustParseAddr("127.0.0.1"), Protocol: layers.IPProtocolICMPv4, TTL: 63}, Message: message}
		proxy := &icmpProxy{srcFunnelTracker: packet.NewFunnelTracker(), listenIP: netip.MustParseAddr("192.0.2.254"), logger: &log, idleTimeout: time.Second}
		require.Error(t, proxy.Request(context.Background(), pk, responder))
		spans := <-muxer.cfdToEdge
		decoded := &tracepb.TracesData{}
		require.NoError(t, proto.Unmarshal(spans.Payload(), decoded))
		span := decoded.ResourceSpans[0].ScopeSpans[0].Spans[0]
		require.Equal(t, "icmp-echo-request", span.Name)
		require.Equal(t, tracepb.Status_STATUS_CODE_ERROR, span.Status.Code)
		require.Equal(t, []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}, span.ParentSpanId)
		require.Len(t, decoded.ResourceSpans[0].ScopeSpans[0].Spans, 1)
	}
}
