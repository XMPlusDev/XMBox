package dispatcher

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxLog "github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"github.com/xmplusdev/xmbox/counter"
	"github.com/xmplusdev/xmbox/limiter"
	"github.com/xmplusdev/xmbox/rate"
	"github.com/xmplusdev/xmbox/rule"
)

var _ adapter.ConnectionTracker = (*Dispatcher)(nil)

// Dispatcher implements sing-box's ConnectionTracker, adding per-user
// traffic counting, rate limiting, and destination rule enforcement.
type Dispatcher struct {
	counter sync.Map // tag → *counter.TrafficCounter
	tracker connTracker
}

// GetTrafficCounter returns the traffic counter for tag, if any.
func (d *Dispatcher) GetTrafficCounter(tag string) (*counter.TrafficCounter, bool) {
	v, ok := d.counter.Load(tag)
	if !ok {
		return nil, false
	}
	return v.(*counter.TrafficCounter), true
}

// RoutedConnection implements adapter.ConnectionTracker for TCP connections.
func (d *Dispatcher) RoutedConnection(
	ctx context.Context,
	conn net.Conn,
	m adapter.InboundContext,
	_ adapter.Rule,
	_ adapter.Outbound,
) net.Conn {
	if m.User == "" {
		return conn
	}

	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		boxLog.Warn("limiter not found for inbound ", m.Inbound, ": ", err)
		return conn
	}

	ip := m.Source.Addr.String()
	bucket, isLimited, reject, reason := l.CheckLimiter(m.Inbound, m.User, ip)
	if reject {
		conn.Close()
		log.Printf("[%s] %s [%s] (TCP) from %s — closed", m.Inbound, reason, m.User, maskIP(ip, 2))
		return newDeadConn(conn)
	}
	if bucket != nil && isLimited {
		conn = rate.NewConn(conn, bucket, bucket)
	}

	if rm, err := rule.GetRuleManager(m.Inbound); err == nil {
		dest := m.Destination.AddrString()
		if rm.CheckRule(m.Inbound, dest) {
			conn.Close()
			log.Printf("[%s] destination [%s] blocked by rule", m.Inbound, dest)
			return newDeadConn(conn)
		}
	}

	t := d.getOrCreateCounter(m.Inbound)

	var deregister func()
	nc := &closeNotifyConn{
		Conn: conn,
		onClose: func() {
			if deregister != nil {
				deregister()
			}
		},
	}
	deregister = d.tracker.add(m.Inbound, m.User, nc)

	return counter.NewConnCounter(nc, t.GetCounter(m.User))
}

// RoutedPacketConnection implements adapter.ConnectionTracker for UDP connections.
func (d *Dispatcher) RoutedPacketConnection(
	ctx context.Context,
	conn N.PacketConn,
	m adapter.InboundContext,
	_ adapter.Rule,
	_ adapter.Outbound,
) N.PacketConn {
	if m.User == "" {
		return conn
	}

	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		boxLog.Warn("limiter not found for inbound ", m.Inbound, ": ", err)
		return conn
	}

	ip := m.Source.Addr.String()
	bucket, isLimited, reject, reason := l.CheckLimiter(m.Inbound, m.User, ip)
	if reject {
		conn.Close()
		log.Printf("[%s] %s [%s] (UDP) from %s — closed", m.Inbound, reason, m.User, maskIP(ip, 2))
		return newDeadPacketConn(conn)
	}
	if bucket != nil && isLimited {
		conn = rate.NewPacketConn(conn, bucket, bucket)
	}

	if rm, err := rule.GetRuleManager(m.Inbound); err == nil {
		dest := m.Destination.AddrString()
		if rm.CheckRule(m.Inbound, dest) {
			conn.Close()
			log.Printf("[%s] destination [%s] blocked by rule", m.Inbound, dest)
			return newDeadPacketConn(conn)
		}
	}

	t := d.getOrCreateCounter(m.Inbound)

	var deregister func()
	nc := &closeNotifyPacketConn{
		PacketConn: conn,
		onClose: func() {
			if deregister != nil {
				deregister()
			}
		},
	}
	deregister = d.tracker.add(m.Inbound, m.User, nc)

	return counter.NewPacketConnCounter(nc, t.GetCounter(m.User))
}

// CloseUserConns forcibly closes all connections for a user in a given tag.
func (d *Dispatcher) CloseUserConns(tag, email string) { d.tracker.closeAll(tag, email) }

// DeleteCounter removes traffic counters for a tag.
func (d *Dispatcher) DeleteCounter(tag string) { d.counter.Delete(tag) }

// ModeList satisfies adapter.ConnectionTracker.
func (d *Dispatcher) ModeList() []string { return nil }

func (d *Dispatcher) getOrCreateCounter(tag string) *counter.TrafficCounter {
	if v, ok := d.counter.Load(tag); ok {
		return v.(*counter.TrafficCounter)
	}
	t := counter.NewTrafficCounter()
	if v, loaded := d.counter.LoadOrStore(tag, t); loaded {
		return v.(*counter.TrafficCounter)
	}
	return t
}

// --- connection tracker ---

type connTracker struct {
	mu      sync.Mutex
	counter uint64
	entries map[string]map[uint64]io.Closer
}

func connKey(tag, email string) string { return tag + "\x00" + email }

func (t *connTracker) add(tag, email string, c io.Closer) func() {
	key := connKey(tag, email)
	id := atomic.AddUint64(&t.counter, 1)

	t.mu.Lock()
	if t.entries == nil {
		t.entries = make(map[string]map[uint64]io.Closer)
	}
	if t.entries[key] == nil {
		t.entries[key] = make(map[uint64]io.Closer)
	}
	t.entries[key][id] = c
	t.mu.Unlock()

	return func() {
		t.mu.Lock()
		if m, ok := t.entries[key]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(t.entries, key)
			}
		}
		t.mu.Unlock()
	}
}

func (t *connTracker) closeAll(tag, email string) {
	key := connKey(tag, email)
	t.mu.Lock()
	conns := t.entries[key]
	delete(t.entries, key)
	t.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// --- close-notify wrappers ---

type closeNotifyConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}
func (c *closeNotifyConn) Upstream() any { return c.Conn }

type closeNotifyPacketConn struct {
	N.PacketConn
	onClose func()
	once    sync.Once
}

func (c *closeNotifyPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.onClose)
	return err
}
func (c *closeNotifyPacketConn) Upstream() any { return c.PacketConn }

// --- dead connection stubs (returned on reject) ---

var errRejected = fmt.Errorf("connection rejected")

type deadConn struct{ net.Conn }

func newDeadConn(c net.Conn) *deadConn        { return &deadConn{c} }
func (d *deadConn) Read([]byte) (int, error)  { return 0, errRejected }
func (d *deadConn) Write([]byte) (int, error) { return 0, errRejected }
func (d *deadConn) Close() error              { return nil }
func (d *deadConn) SetDeadline(time.Time) error { return nil }

type deadPacketConn struct{ N.PacketConn }

func newDeadPacketConn(c N.PacketConn) *deadPacketConn { return &deadPacketConn{c} }
func (d *deadPacketConn) Close() error                  { return nil }

// --- IP masking helper ---

func maskIP(ipStr string, keepSegments int) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.To4() != nil {
		parts := strings.Split(ipStr, ".")
		if len(parts) != 4 {
			return ipStr
		}
		for i := keepSegments; i < 4; i++ {
			parts[i] = "*"
		}
		return strings.Join(parts, ".")
	}
	parts := strings.Split(ip.String(), ":")
	for i := keepSegments; i < len(parts); i++ {
		parts[i] = "*"
	}
	return strings.Join(parts, ":")
}
