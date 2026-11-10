//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindTunnel(dialer *net.Dialer, name string) error {
	if _, err := unix.NewIfreq(name); err != nil {
		return fmt.Errorf("backbone %s: %w", name, err)
	}
	dialer.Control = func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			bindErr = bindTunnelSocket(int(fd), name)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}

func bindTunnelSocket(fd int, name string) error {
	// The service permits INET sockets only. Query the interface on the
	// existing socket without opening a separate netlink socket.
	req, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, req); err != nil {
		return fmt.Errorf("backbone %s: %w", name, err)
	}
	index := int(req.Uint32())
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return fmt.Errorf("backbone %s: %w", name, err)
	}
	const required = unix.IFF_UP | unix.IFF_POINTOPOINT
	if req.Uint16()&required != required || req.Uint16()&unix.IFF_LOOPBACK != 0 {
		return fmt.Errorf("backbone %s: active point-to-point interface required", name)
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, index)
}
