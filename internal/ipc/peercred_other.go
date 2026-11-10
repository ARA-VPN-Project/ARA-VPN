//go:build !linux

package ipc

import (
	"fmt"
	"net"
)

// checkPeer is the non-Linux stub. Darwin lacks SO_PEERCRED through this
// API path; isolation there relies on the 0600 socket mode inside a 0700
// state directory. Production Debian targets always compile the Linux
// implementation (docs/SECURITY_REVIEW_NOTES.md documents this gap).
func (s *Server) checkPeer(conn net.Conn) error {
	if _, ok := conn.(*net.UnixConn); !ok {
		return fmt.Errorf("non-unix connection")
	}
	return nil
}
