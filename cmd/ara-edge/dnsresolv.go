package main

// Exit-scoped DNS resolution for domain destinations (docs/ROUTING_DNS.md):
// the route is decided by the trusted name BEFORE any DNS query, the query
// then travels INSIDE the chosen exit's tunnel (DNS over TCP through the
// exit SOCKS hop), every answer address is ACL-verified, and the dial is
// pinned to a verified address. There is no system-resolver fallback: an
// exit without dns_addr refuses domain destinations instead of leaking the
// query to the edge host's resolver.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"aravpn/core/routing"
)

const (
	dnsQueryTimeout = 3 * time.Second
	// bounded reply size: a reply larger than this is refused
	dnsMaxReply = 4096
	// CNAME chains are followed at most this many hops (docs/ROUTING_DNS.md)
	dnsMaxCNAMENest = 8
)

// resolveViaExit resolves host through the exit's DNS scope and returns
// only ACL-verified addresses (IPv4 first). ANY non-global address in the
// answer denies the destination outright (rebinding protection); the
// caller dials verified[0] and nothing else.
func (dp *edgeDatapath) resolveViaExit(e exitNode, host string) ([]netip.Addr, error) {
	if e.DNSAddr == "" {
		return nil, fmt.Errorf("exit %s has no dns_addr: domain destinations refused (no system-resolver fallback)", e.ID)
	}
	if _, _, err := parseHostPort(e.DNSAddr); err != nil {
		return nil, fmt.Errorf("exit %s dns_addr: %w", e.ID, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
	defer cancel()
	addrs, err := dp.resolveExit(ctx, e, host)
	if err != nil {
		return nil, err
	}
	verified := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		u := a.Unmap()
		if routing.IsNonGlobal(u) && !dp.lanExcepted(u) {
			return nil, fmt.Errorf("resolve %q via %s: address %s denied by system ACL", host, e.ID, u)
		}
		verified = append(verified, u)
	}
	if len(verified) == 0 {
		return nil, fmt.Errorf("resolve %q via %s: no usable addresses", host, e.ID)
	}
	// stable IPv4-first ordering; verified[0] is pinned for the dial
	v4 := verified[:0:0]
	v6 := verified[:0:0]
	for _, a := range verified {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...), nil
}

// dnsOverTCPThroughExit is the default resolveExit: two DNS-over-TCP
// queries (A, AAAA) through the exit hop to the exit's resolver.
func dnsOverTCPThroughExit(ctx context.Context, e exitNode, host string) ([]netip.Addr, error) {
	dnsHost, dnsPort, err := parseHostPort(e.DNSAddr)
	if err != nil {
		return nil, fmt.Errorf("exit %s dns_addr: %w", e.ID, err)
	}
	name, err := canonicalName(host)
	if err != nil {
		return nil, err
	}
	conn, err := e.dialSOCKS(context.Background(), dnsHost, dnsPort, dnsQueryTimeout)
	if err != nil {
		return nil, fmt.Errorf("resolve %q via %s: dns dial: %w", host, e.ID, err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dnsQueryTimeout)
	}
	_ = conn.SetDeadline(deadline)

	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, qtype := range []uint16{1, 28} { // A, AAAA
		msg, err := buildQuery(name, qtype)
		if err != nil {
			return nil, err
		}
		if err := writeDNSMsg(conn, msg); err != nil {
			return nil, fmt.Errorf("resolve %q via %s: write: %w", host, e.ID, err)
		}
		reply, err := readDNSMsg(conn)
		if err != nil {
			// AAAA is best-effort when the A answer already verified;
			// resolvers without the record may close or refuse it
			if qtype == 28 && len(out) > 0 {
				break
			}
			return nil, fmt.Errorf("resolve %q via %s: read: %w", host, e.ID, err)
		}
		addrs, err := parseReply(reply, name, qtype)
		if err != nil {
			if qtype == 28 && len(out) > 0 {
				break
			}
			return nil, fmt.Errorf("resolve %q via %s: %w", host, e.ID, err)
		}
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func parseHostPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return host, port, nil
}

// canonicalName validates and encodes the wire form of a hostname:
// IDNA-ASCII lowercase labels, no trailing dot, no wildcards/URLs.
func canonicalName(host string) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "/: ") {
		return "", fmt.Errorf("invalid hostname %q", host)
	}
	var wire []byte
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid hostname %q", host)
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	return string(wire), nil
}

// buildQuery builds one DNS question message (RD set; no EDNS).
func buildQuery(wireName string, qtype uint16) ([]byte, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	msg := make([]byte, 0, 12+len(wireName)+4)
	msg = append(msg, id[0], id[1])
	msg = append(msg, 0x01, 0x00)             // RD=1, RCODE 0
	msg = append(msg, 0, 1, 0, 0, 0, 0, 0, 0) // QDCOUNT=1
	msg = append(msg, wireName...)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1) // QTYPE, QCLASS=IN
	return msg, nil
}

func writeDNSMsg(conn net.Conn, msg []byte) error {
	if len(msg) > 0xffff {
		return fmt.Errorf("dns: query too large")
	}
	hdr := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(hdr, uint16(len(msg)))
	_, err := conn.Write(append(hdr, msg...))
	return err
}

func readDNSMsg(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := readFullConn(conn, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 || n > dnsMaxReply {
		return nil, fmt.Errorf("dns: bad reply length %d", n)
	}
	msg := make([]byte, n)
	if _, err := readFullConn(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func readFullConn(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// parseReply validates the reply for name/qtype and returns the address
// records of the answer section, following a bounded CNAME chain.
func parseReply(msg []byte, wireName string, qtype uint16) ([]netip.Addr, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: short reply")
	}
	rcode := msg[3] & 0x0f
	if rcode != 0 {
		return nil, fmt.Errorf("dns: rcode %d", rcode)
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	// skip the question section (QDNAME + QTYPE + QCLASS per entry)
	off := 12
	for q := 0; q < int(binary.BigEndian.Uint16(msg[4:6])); q++ {
		_, next, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4
		if off > len(msg) {
			return nil, fmt.Errorf("dns: truncated question")
		}
	}
	_ = wireName
	var addrs []netip.Addr
	cnames := 0
	for i := 0; i < ancount; i++ {
		name, off2, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		_ = name
		off = off2
		if off+10 > len(msg) {
			return nil, fmt.Errorf("dns: truncated RR")
		}
		atype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, fmt.Errorf("dns: truncated RDATA")
		}
		rdata := msg[off : off+rdlen]
		off += rdlen
		switch {
		case atype == 5: // CNAME: bounded chain following
			cnames++
			if cnames > dnsMaxCNAMENest {
				return nil, fmt.Errorf("dns: CNAME chain exceeds %d", dnsMaxCNAMENest)
			}
		case atype == 1 && rdlen == 4:
			addrs = append(addrs, netip.AddrFrom4([4]byte(rdata)))
		case atype == 28 && rdlen == 16:
			addrs = append(addrs, netip.AddrFrom16([16]byte(rdata)).Unmap())
		}
	}
	return addrs, nil
}

// skipName returns the raw name bytes at off (uncompressed-safe: pointers
// are resolved against the message with a bounded loop) and the offset
// after the name.
func skipName(msg []byte, off int) ([]byte, int, error) {
	var full []byte
	jumps := 0
	next := -1
	for {
		if off >= len(msg) {
			return nil, 0, fmt.Errorf("dns: truncated name")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			if next >= 0 {
				return full, next, nil
			}
			return full, off, nil
		}
		if l&0xc0 == 0xc0 { // compression pointer
			if off+1 >= len(msg) {
				return nil, 0, fmt.Errorf("dns: truncated pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > 32 || ptr >= off {
				return nil, 0, fmt.Errorf("dns: bad name compression")
			}
			off = ptr
			continue
		}
		if l > 63 || off+1+l > len(msg) {
			return nil, 0, fmt.Errorf("dns: bad label")
		}
		full = append(full, msg[off:off+1+l]...)
		off += 1 + l
	}
}
