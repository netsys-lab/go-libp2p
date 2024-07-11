package scionquicreuse

import (
	"context"
	"time"

	saddr "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
)

type scionContext struct {
	sciond  daemon.Connector
	localIA saddr.IA
}

const (
	initTimeout = 1 * time.Second
)

func initScionContext() (*scionContext, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	defer cancel()

	sciond, err := findSciond(ctx)
	if err != nil {
		return nil, err
	}

	localIA, err := sciond.LocalIA(ctx)
	if err != nil {
		return nil, err
	}

	return &scionContext{
		sciond:  sciond,
		localIA: localIA,
	}, nil
}

func findSciond(ctx context.Context) (daemon.Connector, error) {
	address := daemon.DefaultAPIAddress

	sciond, err := daemon.NewService(address).Connect(ctx)
	if err != nil {
		return nil, err
	}

	return sciond, nil
}
