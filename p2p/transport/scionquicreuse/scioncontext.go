package scionquicreuse

import (
	"context"
	"fmt"
	"os"
	"time"

	saddr "github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/sock/reliable"
)

type scionContext struct {
	sciond     daemon.Connector
	localIA    saddr.IA
	dispatcher reliable.Dispatcher
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

	dispatcher, err := findDispatcher()
	if err != nil {
		return nil, err
	}

	return &scionContext{
		sciond:     sciond,
		localIA:    localIA,
		dispatcher: dispatcher,
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

func findDispatcher() (reliable.Dispatcher, error) {
	path := reliable.DefaultDispPath

	fileinfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("unable to find dispatcher at %s: %w", path, err)
	}

	if fileinfo.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("dispatcher at %s is not a socket", path)
	}

	return reliable.NewDispatcher(path), nil
}
