package scionquicreuse

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

var quicConfig = &quic.Config{
	MaxIncomingStreams:         256,
	MaxIncomingUniStreams:      5,              // allow some unidirectional streams, in case we speak WebTransport
	MaxStreamReceiveWindow:     10 * (1 << 20), // 10 MB
	MaxConnectionReceiveWindow: 15 * (1 << 20), // 15 MB
	RequireAddressValidation: func(net.Addr) bool {
		// TODO(#1535): require source address validation when under load
		return false
	},
	KeepAlivePeriod: 15 * time.Second,
	Versions:        []quic.VersionNumber{quic.Version1},
	// We don't use datagrams (yet), but this is necessary for WebTransport
	EnableDatagrams: true,
}
