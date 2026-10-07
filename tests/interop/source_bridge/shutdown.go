package tunnel

import (
	"github.com/rs/zerolog"
	"sync"
	"time"
)

func RustInteropWaitToShutdown(wg *sync.WaitGroup, cancel func(), errors <-chan error, grace <-chan struct{}, period time.Duration, log *zerolog.Logger) error {
	return waitToShutdown(wg, cancel, errors, grace, period, log)
}

func RustInteropWaitForSignal(grace chan struct{}) {
	log := zerolog.Nop()
	waitForSignal(grace, &log)
}
