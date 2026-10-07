package connection

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func sourceV3Metric(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if len(metric.Label) != len(labels) {
				continue
			}
			match := true
			for _, label := range metric.Label {
				if labels[label.GetName()] != label.GetValue() {
					match = false
				}
			}
			if match {
				if metric.Gauge != nil {
					return metric.GetGauge().GetValue()
				}
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestPinnedGoV3MetricCreatorRouteAndResponseOutcomes(t *testing.T) {
	creator := sourceV3AckFixture(t)
	migrated := sourceV3SharedAckFixture(t, creator.manager, 1)
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer origin.Close()
	destination := origin.LocalAddr().(*net.UDPAddr).AddrPort()
	labels0 := map[string]string{"conn_index": "0"}
	labels1 := map[string]string{"conn_index": "1"}
	metric := func(name string, labels map[string]string) float64 {
		return sourceV3Metric(t, creator.registry, "cloudflared_udp_"+name, labels)
	}
	first := v3ID(t, 30)
	gate := creator.conn.arm(first, true)
	sendV3Registration(t, creator, first, destination, time.Second)
	waitV3Boundary(t, gate.entered)
	require.Equal(t, float64(1), metric("active_flows", labels0))
	require.Equal(t, float64(1), metric("total_flows", labels0))
	close(gate.release)
	select {
	case <-creator.limiter.released:
	case <-time.After(time.Second):
		t.Fatal("failed creator did not release")
	}
	require.Equal(t, float64(0), metric("active_flows", labels0))
	require.Equal(t, float64(0), metric("failed_flows", labels0))
	id := v3ID(t, 31)
	sendV3Registration(t, creator, id, destination, time.Second)
	receiveV3Response(t, creator, id)
	gate = creator.conn.arm(id, true)
	sendV3Registration(t, creator, id, destination, time.Second)
	waitV3Boundary(t, gate.entered)
	require.Equal(t, float64(0), metric("retry_flow_responses", labels0))
	close(gate.release)
	gate = creator.conn.arm(id, false)
	sendV3Registration(t, creator, id, destination, time.Second)
	waitV3Boundary(t, gate.entered)
	close(gate.release)
	receiveV3Response(t, creator, id)
	require.Eventually(t, func() bool { return metric("retry_flow_responses", labels0) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, float64(2), metric("total_flows", labels0))
	gate = migrated.conn.arm(id, true)
	sendV3Registration(t, migrated, id, destination, time.Second)
	waitV3Boundary(t, gate.entered)
	require.Equal(t, float64(1), metric("migrated_flows", labels1))
	require.Equal(t, float64(1), metric("active_flows", labels0))
	require.Equal(t, float64(0), metric("active_flows", labels1))
	close(gate.release)
	sendV3Payload(t, migrated, id, []byte("announce"))
	require.NoError(t, origin.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 128)
	_, address, err := origin.ReadFromUDP(buffer)
	require.NoError(t, err)
	_, err = origin.WriteToUDP(make([]byte, 1281), address)
	require.NoError(t, err)
	_, err = origin.WriteToUDP(make([]byte, 1501), address)
	require.NoError(t, err)
	_, err = origin.WriteToUDP([]byte("ordered read barrier"), address)
	require.NoError(t, err)
	receiveV3Payload(t, migrated, []byte("ordered read barrier"))
	require.Equal(t, float64(2), metric("dropped_datagrams", map[string]string{"conn_index": "1", "reason": "read_too_large"}))
	sendV3Payload(t, creator, v3ID(t, 99), []byte("unknown"))
	require.Eventually(t, func() bool {
		return metric("dropped_datagrams", map[string]string{"conn_index": "0", "reason": "write_flow_unknown"}) == 1
	}, time.Second, time.Millisecond)
	gate = migrated.conn.armPayload(id, true)
	_, err = origin.WriteToUDP([]byte("failed reply"), address)
	require.NoError(t, err)
	waitV3Boundary(t, gate.entered)
	close(gate.release)
	select {
	case <-creator.limiter.released:
	case <-time.After(time.Second):
		t.Fatal("worker failure did not release")
	}
	require.Equal(t, float64(1), metric("failed_flows", labels1))
	require.Equal(t, float64(0), metric("failed_flows", labels0))
	require.Equal(t, float64(0), metric("active_flows", labels0))
	_, err = creator.handler.RegisterUdpSession(context.Background(), uuid.New(), net.IPv4(127, 0, 0, 1), 53, time.Second, "")
	require.Error(t, err)
	require.Error(t, creator.handler.UnregisterUdpSession(context.Background(), uuid.New(), ""))
	for _, command := range []string{"register_udp_session", "unregister_udp_session"} {
		require.Equal(t, float64(1), metric("unsupported_remote_command_total", map[string]string{"conn_index": "0", "command": command}))
	}
}
