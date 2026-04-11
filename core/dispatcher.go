package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"strings"
	"time"
	logger "log"

	"github.com/xmplusdev/xmbox/helper/counter"
	"github.com/xmplusdev/xmbox/helper/rate"
	"github.com/xmplusdev/xmbox/helper/limiter"
	"github.com/xmplusdev/xmbox/helper/rule"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*Dispatcher)(nil)

type Dispatcher struct {
	counter sync.Map
	tracker connTracker
}

func (d *Dispatcher) GetTrafficCounter(tag string) (*counter.TrafficCounter, bool) {
    v, ok := d.counter.Load(tag)
    if !ok {
        return nil, false
    }
    return v.(*counter.TrafficCounter), true
}

func (d *Dispatcher) RoutedConnection(
	_ context.Context,
	conn net.Conn,
	m adapter.InboundContext,
	_ adapter.Rule,
	_ adapter.Outbound,
) net.Conn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("limiter not found for inbound ", m.Inbound, ": ", err)
		return conn
	}

	ip := m.Source.Addr.String()

	bucket, isSpeedlimited, reject, email := l.CheckLimiter(m.Inbound, m.User, ip)
	if reject {
		conn.Close()
		logger.Printf(fmt.Sprintf("[%s]: IP limit exceeded for [%s]. (TCP) connection from %s closed", m.Inbound, email, maskIP(ip, 2)))
		return newDeadConn(conn)
	}
	if bucket != nil && isSpeedlimited {
		conn = rate.NewConn(conn, bucket, bucket) 
	}
	
	r, err := rule.GetRuleManager(m.Inbound)
	if err == nil {
		dest := m.Destination.AddrString()
		if r.CheckRule(m.Inbound, dest) {
			conn.Close()
			logger.Printf(fmt.Sprintf("[%s] destination [%s] matched restriction rule, connection closed", m.Inbound, dest))
			return newDeadConn(conn)
		}
	}

	if m.User == "" {
		return conn
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

func (d *Dispatcher) RoutedPacketConnection(
	_ context.Context,
	conn N.PacketConn,
	m adapter.InboundContext,
	_ adapter.Rule,
	_ adapter.Outbound,
) N.PacketConn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("limiter not found for inbound ", m.Inbound, ": ", err)
		return conn
	}

	ip := m.Source.Addr.String()

	bucket, isSpeedlimited, reject, email := l.CheckLimiter(m.Inbound, m.User, ip)
	if reject {
		conn.Close()
		logger.Printf(fmt.Sprintf("[%s]: IP limit exceeded for[%s]. (UDP) connection from %s closed", m.Inbound, email, maskIP(ip, 2)))
		return newDeadPacketConn(conn)
	}

	if bucket != nil && isSpeedlimited {
		conn = rate.NewPacketConn(conn, bucket, bucket)
	}
	
	r, err := rule.GetRuleManager(m.Inbound)
	if err == nil {
		dest := m.Destination.AddrString()
		if r.CheckRule(m.Inbound, dest) {
			conn.Close()
			logger.Printf(fmt.Sprintf("[%s] destination [%s] matched restriction rule, connection closed", m.Inbound, dest))
			return newDeadPacketConn(conn)
		}
	}

	if m.User == "" {
		return conn
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

func (d *Dispatcher) CloseUserConns(tag, uuid string) {
	d.tracker.closeAll(tag, uuid)
}

func (d *Dispatcher) DeleteCounter(tag string) {
	d.counter.Delete(tag)
}

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

type connTracker struct {
	mu      sync.Mutex
	counter uint64
	entries map[string]map[uint64]io.Closer
}

func connKey(tag, uuid string) string { return tag + "\x00" + uuid }

func (t *connTracker) add(tag, uuid string, c io.Closer) func() {
	key := connKey(tag, uuid)
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

func (t *connTracker) closeAll(tag, uuid string) {
	key := connKey(tag, uuid)

	t.mu.Lock()
	conns := t.entries[key]
	delete(t.entries, key)
	t.mu.Unlock()

	for _, c := range conns {
		c.Close()
	}
}

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

var errRejected = fmt.Errorf("connection rejected")

type deadConn struct{ net.Conn }

func newDeadConn(c net.Conn) *deadConn           { return &deadConn{c} }
func (d *deadConn) Read([]byte) (int, error)     { return 0, errRejected }
func (d *deadConn) Write([]byte) (int, error)    { return 0, errRejected }
func (d *deadConn) Close() error                 { return nil }
func (d *deadConn) SetDeadline(time.Time) error  { return nil }

type deadPacketConn struct{ N.PacketConn }

func newDeadPacketConn(c N.PacketConn) *deadPacketConn { return &deadPacketConn{c} }
func (d *deadPacketConn) Close() error                 { return nil }

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
	
    fullIP := ip.String()
    parts := strings.Split(fullIP, ":")
    
    for i := keepSegments; i < len(parts); i++ {
        parts[i] = "*"
    }
    
    return strings.Join(parts, ":")
}