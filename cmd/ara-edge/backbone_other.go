//go:build !linux

package main

import (
	"errors"
	"net"
)

func bindTunnel(_ *net.Dialer, _ string) error {
	return errors.New("UNSUPPORTED_CAPABILITY: external backbones require Linux")
}
