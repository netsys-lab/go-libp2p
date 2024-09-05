package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	libp2pscionquic "github.com/libp2p/go-libp2p/p2p/transport/scionquic"
	"github.com/libp2p/go-libp2p/p2p/transport/scionquicreuse"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
)

func usage(prog string) {
	fmt.Printf("Usage: %s <ia> <ip> <port> <nbytes>\n", prog)
}

func main() {
	if len(os.Args) != 5 {
		usage(os.Args[0])
		return
	}
	nbytes, err := strconv.Atoi(os.Args[4])
	if err != nil {
		usage(os.Args[0])
		return
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3], nbytes); err != nil {
		log.Fatalf(err.Error())
	}
}

func run(ia, ip, port string, nbytes int) error {
	addr, err := ma.NewMultiaddr(fmt.Sprintf(
		"/scion/%s/ip4/%s/udp/%s/quic-v1", ia, ip, port))
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
	fmt.Printf("Listening. Now run: go run cmd/client/main.go %s %s\n",
		ln.Multiaddr(), peerID)

	totalRecvd := 0

	var firstConn = true
	var start time.Time

	for {
		// Accept new conn
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		log.Printf("Accepted new connection from %s (%s)\n", conn.RemotePeer(), conn.RemoteMultiaddr())

		// Start timer on first incoming conn
		if firstConn {
			firstConn = false
			start = time.Now()
		}

		// Receive data in parallel
		go func() {
			recvd, err := handleConn(conn)
			if err != nil {
				log.Printf("handling conn failed: %s", err.Error())
			}
			totalRecvd += recvd

			// Stop timer once everything received
			if totalRecvd == nbytes {
				duration := time.Since(start)
				log.Printf("Transfer took %f seconds", duration.Seconds())

				firstConn = true
			}
		}()
	}
}

func handleConn(conn tpt.CapableConn) (recvd int, err error) {
	str, err := conn.AcceptStream()
	if err != nil {
		return 0, err
	}

	// Receive data
	data, err := io.ReadAll(str)
	if err != nil {
		return 0, err
	}
	log.Printf("Received %d bytes\n", len(data))

	// Send reponse
	const msg = "Ok!"
	if _, err := str.Write([]byte(msg)); err != nil {
		return len(data), err
	}

	return len(data), str.Close()
}
