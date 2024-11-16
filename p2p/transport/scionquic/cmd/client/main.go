package main

import (
	"context"
	"crypto/rand"
	"io"
	"strconv"
	"sync"
	"time"

	"fmt"
	"log"
	"os"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	libp2pscionquic "github.com/libp2p/go-libp2p/p2p/transport/scionquic"
	"github.com/libp2p/go-libp2p/p2p/transport/scionquicreuse"
	"github.com/scionproto/scion/pkg/snet"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
)

func usage(prog string) {
	fmt.Printf("Usage: %s <multiaddr> <peer id> <nbytes> <npaths>\n", prog)
}

func main() {
	if len(os.Args) != 5 {
		usage(os.Args[0])
		return
	}
	nbytes, err := strconv.Atoi(os.Args[3])
	if err != nil {
		usage(os.Args[0])
		return
	}
	npaths, err := strconv.Atoi(os.Args[4])
	if err != nil {
		usage(os.Args[0])
		return
	}
	if err := run(os.Args[1], os.Args[2], nbytes, npaths); err != nil {
		log.Fatalf(err.Error())
	}
}

func run(raddr, p string, nbytes, npaths int) error {
	peerID, err := peer.Decode(p)
	if err != nil {
		return err
	}
	addr, err := ma.NewMultiaddr(raddr)
	if err != nil {
		return err
	}
	priv, _, err := ic.GenerateECDSAKeyPair(rand.Reader)
	if err != nil {
		return err
	}

	reuse, err := scionquicreuse.NewConnManager(
		quic.StatelessResetKey{}, quic.TokenGeneratorKey{})
	if err != nil {
		return err
	}
	t, err := libp2pscionquic.NewTransport(priv, reuse, nil, nil, nil)
	if err != nil {
		return err
	}

	// Prepare data to send
	data := make([]byte, nbytes)
	rand.Read(data)

	// Determine paths
	st, ok := t.(tpt.ScionTransport)
	if !ok {
		return fmt.Errorf("not a ScionTransport")
	}
	paths, err := st.QueryPaths(context.Background(), addr)
	if err != nil {
		return err
	}
	if len(paths) < npaths {
		return fmt.Errorf("not enough paths")
	}

	start := time.Now()

	// Parallel transfer
	var wg sync.WaitGroup
	for i := 0; i < npaths; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Determine range to transfer
			slicefrom := i * (nbytes / npaths)
			var sliceto int
			if i < npaths-1 {
				// Split evenly among paths
				sliceto = (i + 1) * (nbytes / npaths)
			} else {
				// Last path gets remainder
				sliceto = slicefrom + (nbytes - (i * (nbytes / npaths)))
			}

			err := transfer(addr, peerID, t,
				data[slicefrom:sliceto], paths[i])
			if err != nil {
				log.Fatal(err)
			}
		}(i)
	}
	wg.Wait()

	duration := time.Since(start)
	log.Printf("Transfer took %f seconds", duration.Seconds())

	return nil
}

func transfer(addr ma.Multiaddr, peerID peer.ID, t tpt.Transport, data []byte,
	path snet.Path) error {

	ctx := context.Background()
	ctx = network.ViaPath(ctx, path)

	// Dial conn via path
	conn, err := t.Dial(ctx, addr, peerID)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Open stream
	str, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	defer str.Close()

	// Transfer data
	log.Printf("Sending %d bytes\n", len(data))
	if _, err := str.Write(data); err != nil {
		return err
	}
	if err := str.CloseWrite(); err != nil {
		return err
	}

	// Read response
	resp, err := io.ReadAll(str)
	if err != nil {
		return err
	}
	log.Printf("Received: %s\n", resp)

	return nil
}
