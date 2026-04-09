package counter

import (
	"sync"
	"sync/atomic"
)

// TrafficCounter holds per-user upload/download byte counters.
// One TrafficCounter is created per inbound tag and stored in the HookServer.
type TrafficCounter struct {
	Counters sync.Map // key: uuid(string) → *TrafficStorage
}

// TrafficStorage holds the atomic counters for one user.
type TrafficStorage struct {
	UpCounter   atomic.Int64
	DownCounter atomic.Int64
}

func NewTrafficCounter() *TrafficCounter {
	return &TrafficCounter{}
}

// GetCounter returns (or lazily creates) the storage for a given UUID.
func (c *TrafficCounter) GetCounter(uuid string) *TrafficStorage {
	if v, ok := c.Counters.Load(uuid); ok {
		return v.(*TrafficStorage)
	}
	s := &TrafficStorage{}
	if v, loaded := c.Counters.LoadOrStore(uuid, s); loaded {
		return v.(*TrafficStorage)
	}
	return s
}

func (c *TrafficCounter) GetUpCount(uuid string) int64 {
	if v, ok := c.Counters.Load(uuid); ok {
		return v.(*TrafficStorage).UpCounter.Load()
	}
	return 0
}

func (c *TrafficCounter) GetDownCount(uuid string) int64 {
	if v, ok := c.Counters.Load(uuid); ok {
		return v.(*TrafficStorage).DownCounter.Load()
	}
	return 0
}

// Reset atomically zeroes the counters for a user.
func (c *TrafficCounter) Reset(uuid string) {
	if v, ok := c.Counters.Load(uuid); ok {
		v.(*TrafficStorage).UpCounter.Store(0)
		v.(*TrafficStorage).DownCounter.Store(0)
	}
}

// Delete removes the counter entry for a user (called on user removal).
func (c *TrafficCounter) Delete(uuid string) {
	c.Counters.Delete(uuid)
}

func (c *TrafficCounter) Len() int {
	n := 0
	c.Counters.Range(func(_, _ interface{}) bool { n++; return true })
	return n
}
