package counter

import (
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

// ─── TCP connection counter ───────────────────────────────────────────────────

// ConnCounter wraps a TCP net.Conn and accumulates per-user traffic bytes into
// a TrafficStorage. Upload (client→server) is counted on Read; download
// (server→client) is counted on Write.
type ConnCounter struct {
	network.ExtendedConn
	storage   *TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
}

func NewConnCounter(conn net.Conn, s *TrafficStorage) net.Conn {
	return &ConnCounter{
		ExtendedConn: bufio.NewExtendedConn(conn),
		storage:      s,
		readFunc:     func(n int64) { s.UpCounter.Add(n) },
		writeFunc:    func(n int64) { s.DownCounter.Add(n) },
	}
}

func (c *ConnCounter) Read(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Read(b)
	if n > 0 {
		c.storage.UpCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) Write(b []byte) (n int, err error) {
	n, err = c.ExtendedConn.Write(b)
	if n > 0 {
		c.storage.DownCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) ReadBuffer(buffer *buf.Buffer) error {
	if err := c.ExtendedConn.ReadBuffer(buffer); err != nil {
		return err
	}
	if buffer.Len() > 0 {
		c.storage.UpCounter.Add(int64(buffer.Len()))
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

// ─── UDP packet connection counter ───────────────────────────────────────────

// PacketConnCounter wraps a UDP network.PacketConn and accumulates traffic.
type PacketConnCounter struct {
	network.PacketConn
	storage   *TrafficStorage
	readFunc  network.CountFunc
	writeFunc network.CountFunc
}

func NewPacketConnCounter(conn network.PacketConn, s *TrafficStorage) network.PacketConn {
	return &PacketConnCounter{
		PacketConn: conn,
		storage:    s,
		readFunc:   func(n int64) { s.UpCounter.Add(n) },
		writeFunc:  func(n int64) { s.DownCounter.Add(n) },
	}
}

func (p *PacketConnCounter) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	dest, err := p.PacketConn.ReadPacket(buffer)
	if err != nil {
		return dest, err
	}
	if buffer.Len() > 0 {
		p.storage.UpCounter.Add(int64(buffer.Len()))
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
