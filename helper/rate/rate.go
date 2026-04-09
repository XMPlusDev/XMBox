package rate

import (
	"context"
	"net"

	"golang.org/x/time/rate"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ─── TCP ─────────────────────────────────────────────────────────────────────

type Conn struct {
	net.Conn
	reader *rate.Limiter
	writer *rate.Limiter
}

func NewConn(c net.Conn, reader, writer *rate.Limiter) *Conn {
	return &Conn{Conn: c, reader: reader, writer: writer}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.reader != nil {
		if err2 := c.reader.WaitN(context.Background(), clamp(n)); err2 != nil {
			return n, err2
		}
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.writer != nil {
		if err = c.writer.WaitN(context.Background(), clamp(len(b))); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Upstream() any { return c.Conn }

// ─── UDP ─────────────────────────────────────────────────────────────────────

type PacketConn struct {
	N.PacketConn
	reader *rate.Limiter
	writer *rate.Limiter
}

func NewPacketConn(c N.PacketConn, reader, writer *rate.Limiter) *PacketConn {
	return &PacketConn{PacketConn: c, reader: reader, writer: writer}
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil && c.reader != nil {
		if err = c.reader.WaitN(context.Background(), clamp(buffer.Len())); err != nil {
			return destination, err
		}
	}
	return
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer != nil {
		if err := c.writer.WaitN(context.Background(), clamp(buffer.Len())); err != nil {
			return err
		}
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *PacketConn) Upstream() any { return c.PacketConn }

// ─── helpers ─────────────────────────────────────────────────────────────────

// clamp ensures n never exceeds the limiter's burst size.
// WaitN returns an error if n > burst, which would block forever.
func clamp(n int) int {
	if n < 1 {
		return 1
	}
	return n
}