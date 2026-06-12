package rate

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

// Conn wraps a net.Conn with separate read and write rate limiters.
type Conn struct {
	net.Conn
	reader *rate.Limiter
	writer *rate.Limiter
}

// NewConn returns a rate-limited connection.
func NewConn(conn net.Conn, reader, writer *rate.Limiter) *Conn {
	return &Conn{Conn: conn, reader: reader, writer: writer}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.reader != nil {
		c.reader.WaitN(context.Background(), n) //nolint:errcheck
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.writer != nil {
		c.writer.WaitN(context.Background(), len(b)) //nolint:errcheck
	}
	return c.Conn.Write(b)
}

func (c *Conn) Upstream() any { return c.Conn }

// PacketConn wraps a sing PacketConn with separate read/write rate limiters.
type PacketConn struct {
	N.PacketConn
	reader *rate.Limiter
	writer *rate.Limiter
}

// NewPacketConn returns a rate-limited packet connection.
func NewPacketConn(conn N.PacketConn, reader, writer *rate.Limiter) *PacketConn {
	return &PacketConn{PacketConn: conn, reader: reader, writer: writer}
}

func (c *PacketConn) Upstream() any { return c.PacketConn }
