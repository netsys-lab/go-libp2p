package scionquicreuse

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

type refCountedQuicTransport interface {
	LocalAddr() net.Addr

	// Used to send packets directly around QUIC. Useful for hole punching.
	WriteTo([]byte, net.Addr) (int, error)

	Close() error

	// count transport reference
	DecreaseCount()
	IncreaseCount()

	Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *quic.Config) (quic.Connection, error)
	Listen(tlsConf *tls.Config, conf *quic.Config) (*quic.Listener, error)
}

type singleOwnerTransport struct {
	quic.Transport

	// Used to write packets directly around QUIC.
	packetConn net.PacketConn
}

func (c *singleOwnerTransport) IncreaseCount() {}
func (c *singleOwnerTransport) DecreaseCount() {
	c.Transport.Close()
}

func (c *singleOwnerTransport) LocalAddr() net.Addr {
	return c.Transport.Conn.LocalAddr()
}

func (c *singleOwnerTransport) Close() error {
	// TODO(when we drop support for go 1.19) use errors.Join
	c.Transport.Close()
	return c.packetConn.Close()
}

func (c *singleOwnerTransport) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Transport.WriteTo(b, addr)
}
