package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	libp2pscionquic "github.com/libp2p/go-libp2p/p2p/transport/scionquic"
	"github.com/libp2p/go-libp2p/p2p/transport/scionquicreuse"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <ia> <port>", os.Args[0])
		return
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		log.Fatalf(err.Error())
	}
}

func run(ia, port string) error {
	addr, err := ma.NewMultiaddr(fmt.Sprintf("/scion/%s/ip4/127.0.0.1/udp/%s/quic-v1", ia, port))
	if err != nil {
		return err
	}
	priv, _, err := ic.GenerateECDSAKeyPair(rand.Reader)
	if err != nil {
		return err
	}
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}

	reuse, err := scionquicreuse.NewConnManager(quic.StatelessResetKey{}, quic.TokenGeneratorKey{})
	if err != nil {
		return err
	}
	t, err := libp2pscionquic.NewTransport(priv, reuse, nil, nil, nil)
	if err != nil {
		return err
	}

	ln, err := t.Listen(addr)
	if err != nil {
		return err
	}
	fmt.Printf("Listening. Now run: go run cmd/client/main.go %s %s\n", ln.Multiaddr(), peerID)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		log.Printf("Accepted new connection from %s (%s)\n", conn.RemotePeer(), conn.RemoteMultiaddr())
		go func() {
			if err := handleConn(conn); err != nil {
				log.Printf("handling conn failed: %s", err.Error())
			}
		}()
	}
}

func handleConn(conn tpt.CapableConn) error {
	str, err := conn.AcceptStream()
	if err != nil {
		return err
	}
	data, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	log.Printf("Received: %s\n", data)
	if _, err := str.Write(data); err != nil {
		return err
	}
	return str.Close()
}
