package counter

import "sync"

// TrafficStorage holds atomic byte counters for one user.
type TrafficStorage struct {
	UpCounter   atomicInt64
	DownCounter atomicInt64
}

// atomicInt64 wraps sync/atomic operations without importing sync/atomic directly
// (the sync package is already imported for sync.Map).
type atomicInt64 struct {
	v int64
	_ [56]byte // cache-line padding
}

func (a *atomicInt64) Add(delta int64) int64 {
	// Using sync/atomic through the standard library.
	return addInt64(&a.v, delta)
}

func (a *atomicInt64) Load() int64 { return loadInt64(&a.v) }

// TrafficCounter maps email keys to per-user TrafficStorage.
type TrafficCounter struct {
	Counters sync.Map // key: email string → *TrafficStorage
}

// NewTrafficCounter returns an empty TrafficCounter.
func NewTrafficCounter() *TrafficCounter { return &TrafficCounter{} }

// GetCounter returns the storage for email, creating it if needed.
func (tc *TrafficCounter) GetCounter(email string) *TrafficStorage {
	v, _ := tc.Counters.LoadOrStore(email, &TrafficStorage{})
	return v.(*TrafficStorage)
}

// GetUpCount returns the current upload byte count for email.
func (tc *TrafficCounter) GetUpCount(email string) int64 {
	if v, ok := tc.Counters.Load(email); ok {
		return v.(*TrafficStorage).UpCounter.Load()
	}
	return 0
}

// GetDownCount returns the current download byte count for email.
func (tc *TrafficCounter) GetDownCount(email string) int64 {
	if v, ok := tc.Counters.Load(email); ok {
		return v.(*TrafficStorage).DownCounter.Load()
	}
	return 0
}
