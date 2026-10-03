package counter

import (
	"net"

	N "github.com/sagernet/sing/common/network"
)

// ConnCounter wraps a net.Conn and counts bytes read/written.
type ConnCounter struct {
	net.Conn
	storage *TrafficStorage
}

// NewConnCounter wraps conn with a traffic counter backed by storage.
func NewConnCounter(conn net.Conn, storage *TrafficStorage) *ConnCounter {
	return &ConnCounter{Conn: conn, storage: storage}
}

func (c *ConnCounter) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.storage.UpCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.storage.DownCounter.Add(int64(n))
	}
	return
}

func (c *ConnCounter) Upstream() any { return c.Conn }

// PacketConnCounter wraps a sing PacketConn and counts bytes.
type PacketConnCounter struct {
	N.PacketConn
	storage *TrafficStorage
}

// NewPacketConnCounter wraps conn with a traffic counter backed by storage.
func NewPacketConnCounter(conn N.PacketConn, storage *TrafficStorage) *PacketConnCounter {
	return &PacketConnCounter{PacketConn: conn, storage: storage}
}

func (c *PacketConnCounter) Upstream() any { return c.PacketConn }
