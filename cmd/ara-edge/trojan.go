package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net"
	"time"

	"aravpn/internal/transport"
)

type bufferedIngress struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedIngress) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedIngress) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (dp *edgeDatapath) handleAccess(conn net.Conn, pinned string) {
	if dp.configSnapshot().TrojanIngress {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		reader := bufio.NewReader(conn)
		first, err := reader.Peek(1)
		if err != nil {
			_ = conn.Close()
			return
		}
		conn = &bufferedIngress{Conn: conn, reader: reader}
		if first[0] != 0 {
			dp.handleTrojan(conn, pinned)
			return
		}
	}
	if pinned == "" {
		dp.handleVLESS(conn)
	} else {
		dp.handleVLESSPinned(conn, pinned)
	}
}

func (dp *edgeDatapath) handleTrojan(conn net.Conn, pinned string) {
	defer conn.Close()
	defer dp.unbind(conn)
	var header [60]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil ||
		header[56] != '\r' || header[57] != '\n' || header[58] != 1 {
		return
	}
	var digest [sha256.Size224]byte
	if _, err := hex.Decode(digest[:], header[:56]); err != nil {
		return
	}
	dev, ok := dp.trojanDevice(digest)
	if !ok {
		return
	}
	host, port, err := socksReadAddr(conn, header[59])
	var end [2]byte
	if err != nil || port == 0 {
		return
	}
	if _, err := io.ReadFull(conn, end[:]); err != nil || end != [2]byte{'\r', '\n'} {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	dp.bindIdentity(conn, dev)
	dp.forwardPinned(conn, host, port, "trojan", pinned)
}

func (dp *edgeDatapath) trojanDevice(digest [sha256.Size224]byte) (deviceAuth, bool) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	var matched deviceAuth
	now := time.Now().Unix()
	for _, device := range dp.devices {
		sum := sha256.Sum224([]byte(transport.TrojanPassword(device.UUID)))
		if subtle.ConstantTimeCompare(digest[:], sum[:]) == 1 &&
			(device.ExpiresUnix == 0 || now < device.ExpiresUnix) {
			matched = device
		}
	}
	return matched, matched.DeviceID != ""
}
