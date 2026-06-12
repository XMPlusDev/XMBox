package scheduler

import (
	"sync"
	"time"
)

// Periodic executes a function at a fixed interval.
type Periodic struct {
	Interval time.Duration
	Execute  func() error
	delay    bool

	access  sync.Mutex
	timer   *time.Timer
	running bool
}

// Start begins periodic execution. If delay is true the first run is deferred
// by one interval; otherwise it fires immediately.
func (t *Periodic) Start() error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.running {
		return nil
	}
	t.running = true
	if t.delay {
		t.timer = time.AfterFunc(t.Interval, t.run)
	} else {
		t.timer = time.AfterFunc(0, t.run)
	}
	return nil
}

// Close stops periodic execution.
func (t *Periodic) Close() error {
	t.access.Lock()
	defer t.access.Unlock()
	t.running = false
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	return nil
}

func (t *Periodic) run() {
	t.Execute() //nolint:errcheck — caller logs errors itself
	t.access.Lock()
	defer t.access.Unlock()
	if t.running {
		t.timer = time.AfterFunc(t.Interval, t.run)
	}
}

// RestartWithInterval changes the interval and immediately resets the timer.
func (t *Periodic) RestartWithInterval(d time.Duration) error {
	t.access.Lock()
	defer t.access.Unlock()
	t.Interval = d
	if t.timer != nil {
		t.timer.Stop()
	}
	if t.running {
		t.timer = time.AfterFunc(d, t.run)
	}
	return nil
}
