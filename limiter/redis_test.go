package limiter

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A zero Timeout used to be passed straight to context.WithTimeout, producing a
// context that was already expired — so every Redis command failed instantly
// with "context deadline exceeded" without Redis ever being contacted.
func TestRedisTimeoutNeverZero(t *testing.T) {
	for _, cfg := range []*RedisConfig{nil, {}, {Timeout: 0}, {Timeout: -1}} {
		got := cfg.timeout()
		if got != defaultRedisTimeout {
			t.Errorf("timeout() = %v for %+v, want the %v default", got, cfg, defaultRedisTimeout)
		}
		ctx, cancel := context.WithTimeout(context.Background(), got)
		err := ctx.Err()
		cancel()
		if err != nil {
			t.Errorf("a context built from %+v was born expired: %v", cfg, err)
		}
	}
	if got := (&RedisConfig{Timeout: 3}).timeout(); got != 3*time.Second {
		t.Errorf("timeout() = %v, want 3s when configured", got)
	}
}

func TestRedisPoolSizeDefault(t *testing.T) {
	for _, cfg := range []*RedisConfig{nil, {}, {PoolSize: 0}, {PoolSize: -5}} {
		if got := cfg.poolSize(); got != defaultRedisPoolSize {
			t.Errorf("poolSize() = %d for %+v, want %d", got, cfg, defaultRedisPoolSize)
		}
	}
	if got := (&RedisConfig{PoolSize: 128}).poolSize(); got != 128 {
		t.Errorf("poolSize() = %d, want 128 when configured", got)
	}
}

// The hash key must not collide with the old format's key, which held a plain
// string — a hash command against it would fail with WRONGTYPE.
func TestIPKeyIsNamespaced(t *testing.T) {
	const subscription = "subscription_1@xmplus.subscription"
	key := ipKey(subscription)
	if key == subscription {
		t.Error("the new key equals the old one; existing string keys would collide")
	}
	if !strings.HasPrefix(key, ipKeyPrefix) {
		t.Errorf("key = %q, want the %q prefix", key, ipKeyPrefix)
	}
}

// Fields encode address and node together, and GetOnlineIPs recovers the
// address by trimming the tag suffix. IPv6 literals are the case that would
// break a naive separator or a split-on-first-match.
func TestIPFieldRoundTrip(t *testing.T) {
	for _, tc := range []struct{ ip, tag string }{
		{"192.0.2.10", "shadowtls_5069_10"},
		{"2001:db8:85a3::8a2e:370:7334", "vmess_443_2"},
		{"::1", "tag_with_underscores_1"},
		{"198.51.100.7", "t"},
	} {
		field := ipField(tc.ip, tc.tag)
		if strings.Count(field, "|") != 1 {
			t.Errorf("field %q has %d separators, want exactly 1", field, strings.Count(field, "|"))
		}
		suffix := "|" + tc.tag
		if !strings.HasSuffix(field, suffix) {
			t.Errorf("field %q does not end with %q", field, suffix)
		}
		if got := strings.TrimSuffix(field, suffix); got != tc.ip {
			t.Errorf("recovered %q, want %q", got, tc.ip)
		}
	}
}

// A field belonging to another node must not be claimed, or two nodes would
// report and delete each other's addresses.
func TestIPFieldTagIsolation(t *testing.T) {
	const ip = "192.0.2.10"
	mine := ipField(ip, "node_a")
	theirs := ipField(ip, "node_b")

	if strings.HasSuffix(theirs, "|node_a") {
		t.Error("another node's field matched this node's suffix")
	}
	if !strings.HasSuffix(mine, "|node_a") {
		t.Error("this node's own field did not match its suffix")
	}
	// A tag that is a suffix of another tag must not match either.
	if strings.HasSuffix(ipField(ip, "prod_node_a"), "|node_a") {
		t.Error("a longer tag ending in the same text was mistaken for this node")
	}
}
