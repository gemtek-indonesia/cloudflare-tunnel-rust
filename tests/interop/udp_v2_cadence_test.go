package datagramsession

import (
	"context"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cloudflare/cloudflared/packet"
	cfdquic "github.com/cloudflare/cloudflared/quic"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPinnedGoV2IdleCadenceStrictAfterAndDuration(t *testing.T) {
	for _, hint := range []time.Duration{0, 8 * time.Nanosecond, 80 * time.Millisecond, 1500 * time.Millisecond} {
		t.Run(hint.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dst, origin := net.Pipe()
				defer origin.Close()
				session := Session{dstConn: dst, activeAtChan: make(chan time.Time, 2), closeChan: make(chan error, 2)}
				done := make(chan error, 1)
				go func() { done <- session.waitForCloseCondition(context.Background(), hint) }()
				synctest.Wait()
				idle := hint
				if idle == 0 {
					idle = 210 * time.Second
				}
				time.Sleep(idle)
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("equality must stay active: %v", err)
				default:
				}
				time.Sleep(idle / 8)
				synctest.Wait()
				require.EqualError(t, <-done, SessionIdleErr(idle).Error())
			})
		})
	}
}

func TestPinnedGoV2TinyAndNegativeHintsPanicInTicker(t *testing.T) {
	for _, hint := range []time.Duration{-1, 1, 2, 3, 4, 5, 6, 7} {
		t.Run(hint.String(), func(t *testing.T) {
			dst, origin := net.Pipe()
			defer origin.Close()
			session := Session{dstConn: dst}
			require.Panics(t, func() { _ = session.waitForCloseCondition(context.Background(), hint) })
		})
	}
}

func TestPinnedGoV2IdleReasonDurationCorpus(t *testing.T) {
	for _, row := range []struct {
		nanos    int64
		expected string
	}{
		{0, "0s"}, {7, "7ns"}, {1001, "1.001µs"}, {1500001, "1.500001ms"}, {1500000001, "1.500000001s"}, {60000000000, "1m0s"}, {3600000000000, "1h0m0s"}, {3661123000000, "1h1m1.123s"}, {9223372036854775807, "2562047h47m16.854775807s"},
	} {
		require.EqualError(t, SessionIdleErr(time.Duration(row.nanos)), "session idle for "+row.expected)
	}
}

func TestPinnedGoV2DroppedReadsStillMarkActivity(t *testing.T) {
	for _, size := range []int{32, 1281, 1600} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dst, origin := net.Pipe()
			defer dst.Close()
			defer origin.Close()
			log := zerolog.Nop()
			mux := cfdquic.NewDatagramMuxerV2(nil, &log, nil)
			send := func(p *packet.Session) error {
				if size == 32 {
					return fmt.Errorf("synthetic transport send failure")
				}
				return mux.SendToSession(p)
			}
			session := Session{dstConn: dst, sendFunc: send, activeAtChan: make(chan time.Time, 2)}
			written := make(chan error, 1)
			go func() { _, err := origin.Write(make([]byte, size)); written <- err }()
			closeSession, err := session.dstToTransport(make([]byte, 1500))
			require.False(t, closeSession)
			require.Error(t, err)
			require.Len(t, session.activeAtChan, 1, "every origin read marks active even when transport drops it")
			if size == 1600 {
				require.Contains(t, err.Error(), "1500 bytes")
				_ = origin.Close()
			}
			<-written
		})
	}
}
