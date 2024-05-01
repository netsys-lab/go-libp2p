package scionquicreuse

import (
	"errors"
	"fmt"
	"net"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	quicV1MA = ma.StringCast("/quic-v1")
)

// DialArgs is a convenience function that returns network and address as
// expected by snet.Dial.
func DialArgs(m ma.Multiaddr) (string, string, error) {
	zone, network, ia, ip, port, err := dialArgComponents(m)
	if err != nil {
		return "", "", err
	}

	switch network {
	case "udp4":
		return network, "[" + ia + "," + ip + "]:" + port, nil
	case "udp6":
		if zone != "" {
			ip += "%" + zone
		}
		return network, "[" + ia + "," + ip + "]:" + port, nil
	default:
		return "", "", fmt.Errorf("%s is not a 'thin waist' address", m)
	}
}

// dialArgComponents extracts the raw pieces used in dialing a Multiaddr
func dialArgComponents(m ma.Multiaddr) (zone, network, ia, ip, port string, err error) {
	ma.ForEach(m, func(c ma.Component) bool {
		switch network {
		case "":
			switch c.Protocol().Code {
			case ma.P_SCION:
				network = "scion"
				ia = c.Value()
				return true
			default:
				return false
			}
		case "scion":
			switch c.Protocol().Code {
			case ma.P_IP6ZONE:
				if zone != "" {
					err = fmt.Errorf("%s has multiple zones", m)
					return false
				}
				zone = c.Value()
				return true
			case ma.P_IP6:
				network = "ip6"
				ip = c.Value()
				return true
			case ma.P_IP4:
				if zone != "" {
					err = fmt.Errorf("%s has ip4 with zone", m)
					return false
				}
				network = "ip4"
				ip = c.Value()
				return true
			default:
				return false
			}
		case "ip4":
			switch c.Protocol().Code {
			case ma.P_UDP:
				network = "udp4"
			default:
				return false
			}
			port = c.Value()
		case "ip6":
			switch c.Protocol().Code {
			case ma.P_UDP:
				network = "udp6"
			default:
				return false
			}
			port = c.Value()
		}
		// Done.
		return false
	})
	return
}

func ToQuicMultiaddr(na net.Addr, version quic.VersionNumber) (ma.Multiaddr, error) {
	if na.Network() != "udp/scion" {
		return nil, fmt.Errorf("unexpected network %s", na.Network())
	}
	sna, ok := na.(*snet.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("not a *snet.UDPAddr")
	}
	scionMA, err := ma.NewMultiaddr(fmt.Sprintf("/scion/%s/", sna.IA))
	if err != nil {
		return nil, err
	}
	udpMA, err := manet.FromNetAddr(sna.Host)
	if err != nil {
		return nil, err
	}
	switch version {
	case quic.Version1:
		addr := scionMA.Encapsulate(udpMA.Encapsulate(quicV1MA))
		return addr, nil
	default:
		return nil, errors.New("unknown QUIC version")
	}
}

func FromQuicMultiaddr(addr ma.Multiaddr) (*snet.UDPAddr, quic.VersionNumber, error) {
	var version quic.VersionNumber
	var partsBeforeQUIC []ma.Multiaddr
	ma.ForEach(addr, func(c ma.Component) bool {
		switch c.Protocol().Code {
		case ma.P_QUIC_V1:
			version = quic.Version1
			return false
		default:
			partsBeforeQUIC = append(partsBeforeQUIC, &c)
			return true
		}
	})
	if len(partsBeforeQUIC) == 0 {
		return nil, version, errors.New("no addr before QUIC component")
	}
	if version == 0 {
		// Not found
		return nil, version, errors.New("unknown QUIC version")
	}
	_, saddr, err := DialArgs(ma.Join(partsBeforeQUIC...))
	if err != nil {
		return nil, version, err
	}
	udpAddr, err := snet.ParseUDPAddr(saddr)
	if err != nil {
		return nil, version, err
	}
	return udpAddr, version, nil
}
