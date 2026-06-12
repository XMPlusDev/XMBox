package scheduler

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// PeriodicTask wraps Periodic with a name and logging.
type PeriodicTask struct {
	LogTag string
	Tag    string
	*Periodic
	mu      sync.Mutex
	running bool
}

// New creates a PeriodicTask that fires immediately on start.
func New(logTag, tag string, interval time.Duration, fn func() error) *PeriodicTask {
	return &PeriodicTask{
		LogTag: logTag,
		Tag:    tag,
		Periodic: &Periodic{
			Interval: interval,
			Execute: func() error {
				if err := fn(); err != nil {
					log.Printf("%s [%s] task error: %v", logTag, tag, err)
				}
				return nil
			},
		},
	}
}

// NewWithDelay creates a PeriodicTask that waits one interval before the first run.
func NewWithDelay(logTag, tag string, interval time.Duration, fn func() error) *PeriodicTask {
	t := New(logTag, tag, interval, fn)
	t.Periodic.delay = true
	return t
}

// Start begins the periodic task.
func (t *PeriodicTask) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}
	t.running = true
	return t.Periodic.Start()
}

// Close stops the periodic task.
func (t *PeriodicTask) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
	return t.Periodic.Close()
}

// RestartWithInterval changes the interval atomically.
func (t *PeriodicTask) RestartWithInterval(d time.Duration) error {
	return t.Periodic.RestartWithInterval(d)
}

// Manager owns a named collection of PeriodicTasks.
type Manager struct {
	tasks []*PeriodicTask
	mu    sync.RWMutex
}

// NewManager returns an empty Manager.
func NewManager() *Manager { return &Manager{} }

// Add registers a task.
func (m *Manager) Add(t *PeriodicTask) {
	m.mu.Lock()
	m.tasks = append(m.tasks, t)
	m.mu.Unlock()
}

// GetTask returns the task with the given tag, or nil.
func (m *Manager) GetTask(tag string) *PeriodicTask {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tasks {
		if t.Tag == tag {
			return t
		}
	}
	return nil
}

// Count returns the number of registered tasks.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tasks)
}

// StartAll starts every registered task.
func (m *Manager) StartAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tasks {
		if err := t.Start(); err != nil {
			return fmt.Errorf("start task %q: %w", t.Tag, err)
		}
	}
	return nil
}

// CloseAll stops every registered task.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, t := range m.tasks {
		if err := t.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close task %q: %w", t.Tag, err)
		}
	}
	m.tasks = nil
	return firstErr
}
