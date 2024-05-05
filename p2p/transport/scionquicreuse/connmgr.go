package scionquicreuse

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
	quiclogging "github.com/quic-go/quic-go/logging"
	saddr "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

type ConnManager struct {
	enableMetrics bool

	serverConfig *quic.Config
	clientConfig *quic.Config

	quicListenersMu sync.Mutex
	quicListeners   map[string]quicListenerEntry

	srk      quic.StatelessResetKey
	tokenKey quic.TokenGeneratorKey

	scionContext *scionContext
	scionNetwork *snet.SCIONNetwork
}

type quicListenerEntry struct {
	refCount int
	ln       *quicListener
}

func NewConnManager(statelessResetKey quic.StatelessResetKey, tokenKey quic.TokenGeneratorKey, opts ...Option) (*ConnManager, error) {
	cm := &ConnManager{
		quicListeners: make(map[string]quicListenerEntry),
		srk:           statelessResetKey,
		tokenKey:      tokenKey,
	}
	for _, o := range opts {
		if err := o(cm); err != nil {
			return nil, err
		}
	}

	// TODO(Leon): Accept options like dispatcher socket
	scionContext, err := initScionContext()
	if err != nil {
		return nil, err
	}
	cm.scionContext = scionContext

	cm.scionNetwork = &snet.SCIONNetwork{
		Dispatcher: &snet.DefaultPacketDispatcherService{
			Dispatcher:  scionContext.dispatcher,
			SCMPHandler: &snet.DefaultSCMPHandler{},
		},
		LocalIA: scionContext.localIA,
	}

	quicConf := quicConfig.Clone()

	quicConf.Tracer = func(ctx context.Context, p quiclogging.Perspective, ci quic.ConnectionID) *quiclogging.ConnectionTracer {
		var tracer *quiclogging.ConnectionTracer
		if qlogTracerDir != "" {
			tracer = qloggerForDir(qlogTracerDir, p, ci)
		}
		return tracer
	}
	serverConfig := quicConf.Clone()

	cm.clientConfig = quicConf
	cm.serverConfig = serverConfig
	return cm, nil
}

func (c *ConnManager) ListenQUIC(addr ma.Multiaddr, tlsConf *tls.Config, allowWindowIncrease func(conn quic.Connection, delta uint64) bool) (Listener, error) {
	netw, host, err := DialArgs(addr)
	if err != nil {
		return nil, err
	}
	laddr, err := snet.ParseUDPAddr(host)
	if err != nil {
		return nil, err
	}

	c.quicListenersMu.Lock()
	defer c.quicListenersMu.Unlock()

	key := laddr.String()
	entry, ok := c.quicListeners[key]
	if !ok {
		tr, err := c.transportForListen(netw, laddr)
		if err != nil {
			return nil, err
		}
		ln, err := newQuicListener(tr, c.serverConfig)
		if err != nil {
			return nil, err
		}
		key = tr.LocalAddr().String()
		entry = quicListenerEntry{ln: ln}
	}
	l, err := entry.ln.Add(tlsConf, allowWindowIncrease, func() { c.onListenerClosed(key) })
	if err != nil {
		if entry.refCount <= 0 {
			entry.ln.Close()
		}
		return nil, err
	}
	entry.refCount++
	c.quicListeners[key] = entry
	return l, nil
}

func (c *ConnManager) onListenerClosed(key string) {
	c.quicListenersMu.Lock()
	defer c.quicListenersMu.Unlock()

	entry := c.quicListeners[key]
	entry.refCount = entry.refCount - 1
	if entry.refCount <= 0 {
		delete(c.quicListeners, key)
		entry.ln.Close()
	} else {
		c.quicListeners[key] = entry
	}
}

func (c *ConnManager) transportForListen(network string, laddr *snet.UDPAddr) (refCountedQuicTransport, error) {
	conn, err := c.scionNetwork.Listen(context.Background(), "udp", laddr.Host, saddr.SvcNone)
	if err != nil {
		return nil, err
	}
	return &singleOwnerTransport{
		packetConn: conn,
		Transport: quic.Transport{
			Conn:              conn,
			StatelessResetKey: &c.srk,
			TokenGeneratorKey: &c.tokenKey,
		},
	}, nil
}

func (c *ConnManager) DialQUIC(ctx context.Context, raddr ma.Multiaddr, tlsConf *tls.Config, allowWindowIncrease func(conn quic.Connection, delta uint64) bool) (quic.Connection, error) {
	naddr, v, err := FromQuicMultiaddr(raddr)
	if err != nil {
		return nil, err
	}
	netw, _, err := DialArgs(raddr)
	if err != nil {
		return nil, err
	}

	quicConf := c.clientConfig.Clone()
	quicConf.AllowConnectionWindowIncrease = allowWindowIncrease

	if v == quic.Version1 {
		// The endpoint has explicit support for QUIC v1, so we'll only use that version.
		quicConf.Versions = []quic.VersionNumber{quic.Version1}
	} else {
		return nil, errors.New("unknown QUIC version")
	}

	tr, err := c.TransportForDial(netw, naddr)
	if err != nil {
		return nil, err
	}

	flags := daemon.PathReqFlags{Refresh: false, Hidden: false}
	paths, err := c.scionContext.sciond.Paths(context.Background(), naddr.IA, 0, flags)
	if err != nil {
		return nil, err
	}
	// TODO(Leon): Implement sensible path selection
	naddr.Path = paths[0].Dataplane()

	conn, err := tr.Dial(ctx, naddr, tlsConf, quicConf)
	if err != nil {
		tr.DecreaseCount()
		return nil, err
	}
	return conn, nil
}

func (c *ConnManager) TransportForDial(network string, raddr *snet.UDPAddr) (refCountedQuicTransport, error) {
	var laddr *net.UDPAddr
	switch network {
	case "udp4":
		laddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	case "udp6":
		laddr = &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	}
	conn, err := c.scionNetwork.Listen(context.Background(), "udp", laddr, saddr.SvcNone)
	if err != nil {
		return nil, err
	}
	return &singleOwnerTransport{Transport: quic.Transport{Conn: conn, StatelessResetKey: &c.srk}, packetConn: conn}, nil
}

func (c *ConnManager) Protocols() []int {
	return []int{ma.P_QUIC_V1}
}

func (c *ConnManager) Close() error {
	return nil
}
