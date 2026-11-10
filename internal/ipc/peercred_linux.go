//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeer verifies the connecting process belongs to the same user as the
// agent (SO_PEERCRED). The socket file mode is the first gate; this is the
// kernel-level second gate (docs/SECURITY.md: typed IPC with peer auth).
func (s *Server) checkPeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("non-unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if cred.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("peer uid %d does not match agent uid %d", cred.Uid, os.Getuid())
	}
	return nil
}
