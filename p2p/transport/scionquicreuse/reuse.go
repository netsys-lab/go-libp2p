package scionquicreuse

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	saddr "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
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

// Constant. Defined as variables to simplify testing.
var (
	garbageCollectInterval = 30 * time.Second
	maxUnusedDuration      = 10 * time.Second
)

type refcountedTransport struct {
	quic.Transport

	// Used to write packets directly around QUIC.
	packetConn net.PacketConn

	mutex       sync.Mutex
	refCount    int
	unusedSince time.Time
}

func (c *refcountedTransport) IncreaseCount() {
	c.mutex.Lock()
	c.refCount++
	c.unusedSince = time.Time{}
	c.mutex.Unlock()
}

func (c *refcountedTransport) Close() error {
	// TODO(when we drop support for go 1.19) use errors.Join
	c.Transport.Close()
	return c.packetConn.Close()
}

func (c *refcountedTransport) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Transport.WriteTo(b, addr)
}

func (c *refcountedTransport) LocalAddr() net.Addr {
	return c.Transport.Conn.LocalAddr()
}

func (c *refcountedTransport) DecreaseCount() {
	c.mutex.Lock()
	c.refCount--
	if c.refCount == 0 {
		c.unusedSince = time.Now()
	}
	c.mutex.Unlock()
}

func (c *refcountedTransport) ShouldGarbageCollect(now time.Time) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return !c.unusedSince.IsZero() && c.unusedSince.Add(maxUnusedDuration).Before(now)
}

type reuse struct {
	mutex sync.Mutex

	closeChan  chan struct{}
	gcStopChan chan struct{}

	unicast map[string] /* IP.String() */ map[int] /* port */ *refcountedTransport

	statelessResetKey *quic.StatelessResetKey
	tokenGeneratorKey *quic.TokenGeneratorKey

	scionNetwork *snet.SCIONNetwork
}

func newReuse(srk *quic.StatelessResetKey, tokenKey *quic.TokenGeneratorKey, scion *snet.SCIONNetwork) *reuse {
	r := &reuse{
		unicast:           make(map[string]map[int]*refcountedTransport),
		closeChan:         make(chan struct{}),
		gcStopChan:        make(chan struct{}),
		statelessResetKey: srk,
		tokenGeneratorKey: tokenKey,
		scionNetwork:      scion,
	}
	go r.gc()
	return r
}

func (r *reuse) gc() {
	defer func() {
		r.mutex.Lock()
		for _, trs := range r.unicast {
			for _, tr := range trs {
				tr.Close()
			}
		}
		r.mutex.Unlock()
		close(r.gcStopChan)
	}()
	ticker := time.NewTicker(garbageCollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			r.mutex.Lock()
			for ukey, trs := range r.unicast {
				for key, tr := range trs {
					if tr.ShouldGarbageCollect(now) {
						tr.Close()
						delete(trs, key)
					}
				}
				if len(trs) == 0 {
					delete(r.unicast, ukey)
				}
			}
			r.mutex.Unlock()
		}
	}
}

func (r *reuse) TransportForDial(network string, raddr *snet.UDPAddr) (*refcountedTransport, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	tr, err := r.transportForDialLocked(network, &raddr.Host.IP)
	if err != nil {
		return nil, err
	}
	tr.IncreaseCount()
	return tr, nil
}

func (r *reuse) transportForDialLocked(network string, source *net.IP) (*refcountedTransport, error) {
	if source != nil {
		// We already have at least one suitable transport...
		if trs, ok := r.unicast[source.String()]; ok {
			// ... we don't care which port we're dialing from. Just use the first.
			for _, tr := range trs {
				return tr, nil
			}
		}
	}

	// We don't have a transport that we can use for dialing.
	// Dial a new connection from a random port.
	var addr *net.UDPAddr
	switch network {
	case "udp4":
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	case "udp6":
		addr = &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	}
	conn, err := r.scionNetwork.Listen(context.Background(), "udp", addr, saddr.SvcNone)
	if err != nil {
		return nil, err
	}
	tr := &refcountedTransport{Transport: quic.Transport{
		Conn:              conn,
		StatelessResetKey: r.statelessResetKey,
		TokenGeneratorKey: r.tokenGeneratorKey,
	}, packetConn: conn}

	unicastIpStr := conn.LocalAddr().(*snet.UDPAddr).Host.IP.String()
	if _, ok := r.unicast[unicastIpStr]; !ok {
		r.unicast[unicastIpStr] = make(map[int]*refcountedTransport)
	}
	r.unicast[unicastIpStr][conn.LocalAddr().(*snet.UDPAddr).Host.Port] = tr

	return tr, nil
}

func (r *reuse) TransportForListen(network string, laddr *snet.UDPAddr) (*refcountedTransport, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if we can reuse a transport we have already dialed out from.
	// We reuse a transport from unicast when the requested port is 0 or the requested
	// port is already in the unicast.
	if trs, ok := r.unicast[laddr.Host.IP.String()]; ok {
		if laddr.Host.Port == 0 {
			// the requested port is 0, we can reuse any transport
			for _, tr := range trs {
				tr.IncreaseCount()
				return tr, nil
			}
		} else if tr, ok := r.unicast[laddr.Host.IP.String()][laddr.Host.Port]; ok {
			tr.IncreaseCount()
			return tr, nil
		}
	}

	conn, err := r.scionNetwork.Listen(context.Background(), "udp", laddr.Host, saddr.SvcNone)
	if err != nil {
		return nil, err
	}
	localAddr := conn.LocalAddr().(*snet.UDPAddr)
	tr := &refcountedTransport{
		Transport: quic.Transport{
			Conn:              conn,
			StatelessResetKey: r.statelessResetKey,
		},
		packetConn: conn,
	}
	tr.IncreaseCount()

	// Deal with listen on a unicast address
	if _, ok := r.unicast[localAddr.Host.IP.String()]; !ok {
		r.unicast[localAddr.Host.IP.String()] = make(map[int]*refcountedTransport)
	}

	// The kernel already checked that the laddr is not already listen
	// so we need not check here (when we create ListenUDP).
	r.unicast[localAddr.Host.IP.String()][localAddr.Host.Port] = tr
	return tr, nil
}

func (r *reuse) Close() error {
	close(r.closeChan)
	<-r.gcStopChan
	return nil
}
