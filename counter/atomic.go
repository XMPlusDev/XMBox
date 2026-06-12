package counter

import "sync/atomic"

func addInt64(v *int64, delta int64) int64  { return atomic.AddInt64(v, delta) }
func loadInt64(v *int64) int64              { return atomic.LoadInt64(v) }
