package counter

import (
	"fmt"
	"io"
	"net"
	"sync"
	
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type DeltaFunc func(upload, download int64) bool

// ─── TCP ─────────────────────────────────────────────────────────────────────

type ConnCounter struct {
	network.ExtendedConn
	storage   *TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
	delta     DeltaFunc  // nil = no quota enforcement
	closeOnce sync.Once
}

func NewConnCounter(conn net.Conn, s *TrafficStorage, delta DeltaFunc) net.Conn {
	return &ConnCounter{
		ExtendedConn: bufio.NewExtendedConn(conn),
		storage:      s,
		readFunc:     func(n int64) { s.UpCounter.Add(n) },
		writeFunc:    func(n int64) { s.DownCounter.Add(n) },
		delta:        delta,
	}
}

func (c *ConnCounter) Read(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Read(b)
	if n > 0 {
		c.storage.UpCounter.Add(int64(n))
		if c.delta != nil && c.delta(int64(n), 0) {
			c.closeOnce.Do(func() { c.ExtendedConn.Close() })
			return n, fmt.Errorf("traffic quota exceeded")
		}
	}
	return
}

func (c *ConnCounter) Write(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Write(b)
	if n > 0 {
		c.storage.DownCounter.Add(int64(n))
		if c.delta != nil && c.delta(0, int64(n)) {
			c.closeOnce.Do(func() { c.ExtendedConn.Close() })
			return n, fmt.Errorf("traffic quota exceeded")
		}
	}
	return
}

func (c *ConnCounter) ReadBuffer(buffer *buf.Buffer) error {
	if err := c.ExtendedConn.ReadBuffer(buffer); err != nil {
		return err
	}
	if buffer.Len() > 0 {
		n := int64(buffer.Len())
		c.storage.UpCounter.Add(n)
		if c.delta != nil && c.delta(n, 0) {
			c.closeOnce.Do(func() { c.ExtendedConn.Close() })
			return fmt.Errorf("traffic quota exceeded")
		}
	}
	return nil
}

func (c *ConnCounter) WriteBuffer(buffer *buf.Buffer) error {
	n := int64(buffer.Len())
	if err := c.ExtendedConn.WriteBuffer(buffer); err != nil {
		return err
	}
	if n > 0 {
		c.storage.DownCounter.Add(n)
		if c.delta != nil && c.delta(0, n) {
			c.closeOnce.Do(func() { c.ExtendedConn.Close() })
			return fmt.Errorf("traffic quota exceeded")
		}
	}
	return nil
}

func (c *ConnCounter) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{c.readFunc}
}
func (c *ConnCounter) UnwrapWriter() (io.Writer, []network.CountFunc) {
	return c.ExtendedConn, []network.CountFunc{c.writeFunc}
}
func (c *ConnCounter) Upstream() any { return c.ExtendedConn }

// ─── UDP ─────────────────────────────────────────────────────────────────────

type PacketConnCounter struct {
	network.PacketConn
	storage   *TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
	delta     DeltaFunc
	closeOnce sync.Once
}

func NewPacketConnCounter(conn network.PacketConn, s *TrafficStorage, delta DeltaFunc) network.PacketConn {
	return &PacketConnCounter{
		PacketConn: conn,
		storage:    s,
		readFunc:   func(n int64) { s.UpCounter.Add(n) },
		writeFunc:  func(n int64) { s.DownCounter.Add(n) },
		delta:      delta,
	}
}

func (p *PacketConnCounter) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	dest, err := p.PacketConn.ReadPacket(buffer)
	if err != nil {
		return dest, err
	}
	if buffer.Len() > 0 {
		n := int64(buffer.Len())
		p.storage.UpCounter.Add(n)
		if p.delta != nil && p.delta(n, 0) {
			p.closeOnce.Do(func() { p.PacketConn.Close() })
			return dest, fmt.Errorf("traffic quota exceeded")
		}
	}
	return dest, nil
}

func (p *PacketConnCounter) WritePacket(buffer *buf.Buffer, dest M.Socksaddr) error {
	n := int64(buffer.Len())
	if err := p.PacketConn.WritePacket(buffer, dest); err != nil {
		return err
	}
	if n > 0 {
		p.storage.DownCounter.Add(n)
		if p.delta != nil && p.delta(0, n) {
			p.closeOnce.Do(func() { p.PacketConn.Close() })
			return fmt.Errorf("traffic quota exceeded")
		}
	}
	return nil
}

func (p *PacketConnCounter) UnwrapPacketReader() (network.PacketReader, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{p.readFunc}
}
func (p *PacketConnCounter) UnwrapPacketWriter() (network.PacketWriter, []network.CountFunc) {
	return p.PacketConn, []network.CountFunc{p.writeFunc}
}
func (p *PacketConnCounter) Upstream() any { return p.PacketConn }