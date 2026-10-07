package v3

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPinnedGoV3IdleRefreshUsesConsumedActivityTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		origin, peer := net.Pipe()
		defer peer.Close()
		log := zerolog.Nop()
		metrics := NewMetrics(prometheus.NewRegistry())
		session := NewSession(RequestID{}, 100*time.Millisecond, origin, nil, nil, nil, metrics, &log).(*session)
		done := make(chan error, 1)
		go func() { done <- session.waitForCloseCondition(context.Background(), 100*time.Millisecond) }()
		synctest.Wait()
		time.Sleep(70 * time.Millisecond)
		session.activeAtChan <- time.Now().Add(-60 * time.Millisecond)
		synctest.Wait()
		time.Sleep(60 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("recorded timestamp must not cause early expiry: %v", err)
		default:
		}
		time.Sleep(40 * time.Millisecond)
		synctest.Wait()
		require.EqualError(t, <-done, "flow was idle for 100ms")
	})
}
