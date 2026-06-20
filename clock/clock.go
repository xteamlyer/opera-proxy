package clock

import (
	"context"
	"time"
)

// AfterWallClock returns a channel that receives after duration d, measured
// against wall-clock time. Unlike time.After, it is resilient to the system
// clock jumping forward (e.g. after a suspend/resume cycle): a second ticker
// fires every second so a large wall-clock jump is detected within 1 s.
//
// Previous implementation spawned a goroutine containing both time.After AND
// time.NewTicker, i.e. two OS timers per call. The new implementation uses
// only time.NewTicker and checks elapsed wall-clock time on each tick, which
// achieves the same goal with one timer and no goroutine leak on the fast
// path (when the deadline has already passed before the first tick).
func AfterWallClock(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	// Guard against time.NewTicker panicking on non-positive durations.
	// A zero or negative interval means "fire immediately".
	if d <= 0 {
		ch <- time.Now()
		return ch
	}
	deadline := time.Now().Add(d)
	ticker := time.NewTicker(time.Second)
	go func() {
		defer ticker.Stop()
		for t := range ticker.C {
			if !t.Before(deadline) {
				ch <- t
				return
			}
		}
	}()
	return ch
}

// RunTicker calls cb in a loop, waiting interval between successful calls
// and retryInterval after a failure. It stops when ctx is cancelled.
func RunTicker(ctx context.Context, interval, retryInterval time.Duration, cb func(context.Context) error) {
	go func() {
		var err error
		for {
			nextInterval := interval
			if err != nil {
				nextInterval = retryInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-AfterWallClock(nextInterval):
				err = cb(ctx)
			}
		}
	}()
}
