// Package transport implements the minimal VLESS-over-TLS data path used
// by the ara-edge component (review: transport slice). VLESS wire format:
// request [ver][uuid:16][addonLen][addon][cmd][port:2 BE][addrType][addr],
// response [ver][addonLen][addon]. inner TCP streams are relayed byte-wise.
package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var ErrUnknownAddrType = errors.New("vless: unknown address type")

// ParseRequest reads a VLESS request header from r.
func ParseRequest(r io.Reader) (uuid [16]byte, cmd byte, addrStr string, port int, err error) {
	hdr := make([]byte, 1+16+1)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != 0 {
		err = fmt.Errorf("vless: unsupported version %d", hdr[0])
		return
	}
	copy(uuid[:], hdr[1:17])
	addonLen := hdr[17]
	if addonLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(addonLen)); err != nil {
			return
		}
	}
	var rest []byte
	if cmd, err = readByte(r); err != nil {
		return
	}
	rest = make([]byte, 2+1)
	if _, err = io.ReadFull(r, rest); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(rest[0:2]))
	at := rest[2]
	switch at {
	case 1: // IPv4
		ip := make([]byte, 4)
		if _, err = io.ReadFull(r, ip); err != nil {
			return
		}
		addrStr = net.IP(ip).String()
	case 2: // domain
		l, e2 := readByte(r)
		if e2 != nil {
			err = e2
			return
		}
		d := make([]byte, l)
		if _, err = io.ReadFull(r, d); err != nil {
			return
		}
		addrStr = string(d)
	case 3: // IPv6
		ip := make([]byte, 16)
		if _, err = io.ReadFull(r, ip); err != nil {
			return
		}
		addrStr = net.IP(ip).String()
	default:
		err = ErrUnknownAddrType
	}
	return
}

// WriteAccept writes the VLESS server response: [ver=0][addonLen=0]. The
// version byte is part of the response frame (upstream XTLS/Xray-core
// encoding.go); a bare 0x00 would be read by the client as the addon
// length and leak the real response into the payload stream.
func WriteAccept(w io.Writer) error {
	_, err := w.Write([]byte{0, 0})
	return err
}

// ClientHandshake writes a VLESS client request over an established
// (TLS) connection and consumes the server response frame
// ([ver][addonLen][addon]); payload bytes after the frame belong to the
// application stream and are left in the connection.
func ClientHandshake(c net.Conn, uuid [16]byte, addr string, port int) error {
	hdr := []byte{0}
	hdr = append(hdr, uuid[:]...)
	hdr = append(hdr, 0) // addonLen
	hdr = append(hdr, 1) // cmd TCP
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	hdr = append(hdr, p[:]...)
	if ip := parseIP(addr); ip != nil {
		if ip.To4() != nil {
			hdr = append(hdr, 1)
			hdr = append(hdr, ip.To4()...)
		} else {
			hdr = append(hdr, 3)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		hdr = append(hdr, 2, byte(len(addr)))
		hdr = append(hdr, addr...)
	}
	if err := writeFull(c, hdr); err != nil {
		return err
	}
	var ack [2]byte
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return fmt.Errorf("vless: no accept: %w", err)
	}
	if ack[0] != 0 {
		_ = c.SetReadDeadline(time.Time{})
		return fmt.Errorf("vless: unsupported response version %d", ack[0])
	}
	if addonLen := int64(ack[1]); addonLen > 0 {
		if _, err := io.CopyN(io.Discard, c, addonLen); err != nil {
			return fmt.Errorf("vless: short response addons: %w", err)
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return nil
}

// DialVLESS opens a VLESS-over-TLS client stream to dst.
func DialVLESS(tlsConf *tls.Config, server string, uuid [16]byte, addr string, port int, timeout time.Duration) (net.Conn, error) {
	d := &tls.Dialer{Config: tlsConf, NetDialer: &net.Dialer{Timeout: timeout}}
	conn, err := d.DialContext(context.Background(), "tcp", server)
	if err != nil {
		return nil, err
	}
	if err := ClientHandshake(conn, uuid, addr, port); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func writeFull(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
