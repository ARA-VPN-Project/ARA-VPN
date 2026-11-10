// Command ara-dns-responder is a minimal lab DNS server: it answers A
// queries for the configured zone with the configured address and
// forwards nothing (isolated lab canary only). Both UDP and TCP.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

func buildResponse(q []byte, ip net.IP) []byte {
	if len(q) < 12 {
		return nil
	}
	// echo header with AA=1, RCODE=0, ANCOUNT=1
	resp := append([]byte{}, q...)
	resp[2] |= 0x84 // QR=1, AA=1
	resp[3] = resp[3]&0x7f | 0 // RCODE 0
	binary.BigEndian.PutUint16(resp[6:8], 1)
	// question echo already present; append answer (the name field must
	// keep its terminating zero byte, otherwise the whole RR shifts)
	name := append([]byte{}, q[12:12+nameLen(q)]...)
	resp = append(resp, name...)
	resp = append(resp, 0x00)                   // name terminator
	resp = append(resp, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL 60
	resp = append(resp, 0x00, 0x04)             // rdlength 4
	resp = append(resp, ip.To4()...)
	return resp
}

func nameLen(q []byte) int {
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	return i - 12
}

func queryName(q []byte) string {
	if len(q) < 12 {
		return ""
	}
	var parts []string
	i := 12
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			break
		}
		parts = append(parts, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(parts, ".")
}

func main() {
	zone := flag.String("zone", "canary.ara.lab", "zone to answer for")
	answer := flag.String("answer", "10.71.1.1", "A record answer")
	listen := flag.String("listen", ":53", "listen addr (UDP+TCP)")
	flag.Parse()
	zonePtr := strings.TrimSuffix(*zone, ".") + "."
	zone = &zonePtr

	udpAddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("dns responder zone=%s answer=%s listen=%s\n", *zone, *answer, *listen)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					// DNS over TCP allows several queries per connection;
					// clients (ara-edge resolves A and AAAA) rely on it
					var l [2]byte
					if _, err := readFull(c, l[:]); err != nil {
						return
					}
					msg := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := readFull(c, msg); err != nil {
						return
					}
					if !zoneMatches(msg, *zone) {
						return
					}
					r := buildResponse(msg, net.ParseIP(*answer))
					out := make([]byte, 2+len(r))
					binary.BigEndian.PutUint16(out[:2], uint16(len(r)))
					copy(out[2:], r)
					if _, err := c.Write(out); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := buf[:n]
		if !zoneMatches(msg, *zone) {
			continue
		}
		if r := buildResponse(msg, net.ParseIP(*answer)); r != nil {
			conn.WriteToUDP(r, remote)
		}
	}
}

// zoneMatches compares the wire query name against the configured zone:
// the wire form carries no trailing dot, the configured zone does, so both
// are normalized before the suffix check (a bare HasSuffix always failed
// and silently closed every connection — found by the exit-scoped DNS E2E).
func zoneMatches(msg []byte, zone string) bool {
	if len(msg) < 12 {
		return false
	}
	name := strings.TrimSuffix(queryName(msg), ".") + "."
	return strings.HasSuffix(name, zone)
}

func readFull(c net.Conn, b []byte) (int, error) {
	t := 0
	for t < len(b) {
		n, err := c.Read(b[t:])
		t += n
		if err != nil {
			return t, err
		}
	}
	return t, nil
}
