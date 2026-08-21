package subscription

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/xmplusdev/xmbox/api"
	"github.com/xmplusdev/xmbox/counter"
	"github.com/xmplusdev/xmbox/limiter"
)

// reverbMaxMessageSize is Reverb's default per-message ceiling
// (config/reverb.php: max_message_size). A batch that exceeds it is rejected on
// receipt, which the sender cannot see.
const reverbMaxMessageSize = 10_000

// stubAPI records what reached the HTTP fallback.
type stubAPI struct {
	api.API
	reported []api.SubscriptionTraffic
	err      error
	calls    int
}

func (s *stubAPI) ReportTraffic(traffic *[]api.SubscriptionTraffic) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.reported = append(s.reported, *traffic...)
	return nil
}

// pendingWith builds n records, each backed by its own live counter so resets
// are observable.
func pendingWith(n int) (*limiter.PendingTraffic, []*counter.TrafficStorage) {
	tc := counter.NewTrafficCounter()
	pending := &limiter.PendingTraffic{}
	stores := make([]*counter.TrafficStorage, 0, n)
	for i := range n {
		email := string(rune('a'+i%26)) + string(rune('0'+i/26))
		s := tc.GetCounter(email)
		s.UpCounter.Add(1000)
		s.DownCounter.Add(2000)
		stores = append(stores, s)
		pending.Add(api.SubscriptionTraffic{Id: i + 1, Upload: 1000, Download: 2000}, s, 1000, 2000)
	}
	return pending, stores
}

func totals(stores []*counter.TrafficStorage) (int64, int64) {
	var up, down int64
	for _, s := range stores {
		up += s.UpCounter.Load()
		down += s.DownCounter.Load()
	}
	return up, down
}

// A batch has to stay under Reverb's ceiling by construction, because going
// over it is not reported back to the sender.
func TestReverbBatchFitsMessageLimit(t *testing.T) {
	traffic := make([]api.Traffic, reverbBatchSize)
	for i := range traffic {
		// Worst case: full-width int64 counters and a large id.
		traffic[i] = api.Traffic{Id: 2147483647, Upload: 9223372036854775807, Download: 9223372036854775807}
	}
	data, err := json.Marshal(traffic)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{
		"event":   "client-traffic_report",
		"channel": "private-xmplus",
		"data":    json.RawMessage(data),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) >= reverbMaxMessageSize {
		t.Errorf("a full batch marshals to %d bytes, at or over Reverb's %d-byte limit", len(envelope), reverbMaxMessageSize)
	}
	t.Logf("worst-case batch of %d records = %d bytes", reverbBatchSize, len(envelope))
}

// Every record is delivered, across as many messages as it takes, and the
// counters are cleared.
func TestReportTrafficChunksAndResets(t *testing.T) {
	pending, stores := pendingWith(250)
	client := &stubAPI{}
	m := &Manager{client: client}

	var batches [][]api.Traffic
	pusher := func(event string, data any) error {
		if event != "traffic_report" {
			t.Errorf("event = %q", event)
		}
		batches = append(batches, data.([]api.Traffic))
		return nil
	}

	m.reportTraffic(pending, "[test]", pusher)

	if len(batches) != 3 {
		t.Errorf("sent %d messages, want 3 for 250 records at %d per batch", len(batches), reverbBatchSize)
	}
	delivered := 0
	for _, b := range batches {
		if len(b) > reverbBatchSize {
			t.Errorf("a batch carried %d records, over the %d limit", len(b), reverbBatchSize)
		}
		delivered += len(b)
	}
	if delivered != 250 {
		t.Errorf("delivered %d records, want 250", delivered)
	}
	if up, down := totals(stores); up != 0 || down != 0 {
		t.Errorf("counters left at up=%d down=%d, want 0 after a successful push", up, down)
	}
	if client.calls != 0 {
		t.Errorf("HTTP fallback ran %d times despite every push succeeding", client.calls)
	}
}

// A push failure must fall back to HTTP rather than reset — the bug that lost
// traffic when Reverb rejected an oversized message.
func TestReportTrafficFallsBackOnPushFailure(t *testing.T) {
	pending, stores := pendingWith(10)
	client := &stubAPI{}
	m := &Manager{client: client}

	m.reportTraffic(pending, "[test]", func(string, any) error {
		return errors.New("maximum message size exceeded")
	})

	if len(client.reported) != 10 {
		t.Errorf("HTTP fallback got %d records, want all 10", len(client.reported))
	}
	if up, down := totals(stores); up != 0 || down != 0 {
		t.Errorf("counters left at up=%d down=%d, want 0 after the fallback succeeded", up, down)
	}
}

// If both layers fail the counters survive, so the traffic is reported next
// cycle instead of vanishing.
func TestReportTrafficKeepsCountersWhenBothFail(t *testing.T) {
	pending, stores := pendingWith(10)
	client := &stubAPI{err: errors.New("panel down")}
	m := &Manager{client: client}

	m.reportTraffic(pending, "[test]", func(string, any) error {
		return errors.New("push failed")
	})

	up, down := totals(stores)
	if up != 10*1000 || down != 10*2000 {
		t.Errorf("counters at up=%d down=%d, want them untouched so the next cycle retries", up, down)
	}
}

// A batch that fails must not take the ones that already landed with it, and
// must not keep counters for records it did deliver.
func TestReportTrafficPartialFailure(t *testing.T) {
	pending, stores := pendingWith(250)
	client := &stubAPI{}
	m := &Manager{client: client}

	call := 0
	m.reportTraffic(pending, "[test]", func(string, any) error {
		call++
		if call == 2 {
			return errors.New("push failed")
		}
		return nil
	})

	// Batch 2 is the only one that failed, so exactly its records go to HTTP.
	if len(client.reported) != reverbBatchSize {
		t.Errorf("HTTP fallback got %d records, want the %d from the failed batch", len(client.reported), reverbBatchSize)
	}
	if up, down := totals(stores); up != 0 || down != 0 {
		t.Errorf("counters left at up=%d down=%d, want 0 once every batch was accounted for", up, down)
	}
}

// Chunk must slice records and their counters by the same index, or a batch
// would reset counters belonging to different subscriptions.
func TestChunkKeepsCountersAligned(t *testing.T) {
	pending, stores := pendingWith(5)
	chunks := pending.Chunk(2)
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}

	// Resetting only the first chunk must clear exactly its two counters.
	limiter.ResetTraffic(chunks[0])
	for i, s := range stores {
		up := s.UpCounter.Load()
		if i < 2 && up != 0 {
			t.Errorf("counter %d = %d, want 0 — it was in the reset chunk", i, up)
		}
		if i >= 2 && up != 1000 {
			t.Errorf("counter %d = %d, want 1000 — it was not in the reset chunk", i, up)
		}
	}
}

func TestChunkEdgeCases(t *testing.T) {
	if got := (*limiter.PendingTraffic)(nil).Chunk(10); got != nil {
		t.Errorf("nil pending gave %v, want nil", got)
	}
	if got := (&limiter.PendingTraffic{}).Chunk(10); got != nil {
		t.Errorf("empty pending gave %v, want nil", got)
	}
	pending, _ := pendingWith(3)
	if got := pending.Chunk(10); len(got) != 1 || len(got[0].Result) != 3 {
		t.Errorf("a batch smaller than the size should stay whole, got %d chunks", len(got))
	}
	if got := pending.Chunk(0); len(got) != 1 {
		t.Errorf("size 0 should not divide, got %d chunks", len(got))
	}
}
