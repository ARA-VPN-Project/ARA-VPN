package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"aravpn/core/routing"
	"aravpn/internal/controlstore"
)

type NodeCheckStep struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type NodeCheckResult struct {
	NodeID string          `json:"node_id"`
	Source string          `json:"source"`
	Steps  []NodeCheckStep `json:"steps"`
}

func CheckNodeIngress(ctx context.Context, node controlstore.Node) NodeCheckResult {
	result := NodeCheckResult{NodeID: node.ID, Source: "checker_host",
		Steps: []NodeCheckStep{{Name: "dns", Status: "skipped"}, {Name: "tcp", Status: "skipped"}, {Name: "tls", Status: "skipped"}}}
	fail := func(index int, reason string) NodeCheckResult {
		result.Steps[index].Status = "failed"
		result.Steps[index].Reason = reason
		return result
	}
	ok := func(index int, start time.Time) {
		result.Steps[index].Status = "ok"
		result.Steps[index].DurationMS = time.Since(start).Milliseconds()
	}
	if node.IngressAddr == "" {
		result.Steps[0].Reason = "no_ingress"
		return result
	}
	host, port, err := net.SplitHostPort(node.IngressAddr)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil || p < 1 || p > 65535 || host == "" {
		return fail(0, "invalid_endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	start := time.Now()
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
		result.Steps[0].Reason = "ip_literal"
	} else {
		addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return fail(0, "resolve_failed")
		}
	}
	// Pin every dial to a vetted address. No private, loopback, transition
	// or metadata destination can be probed through the admin API.
	publicV6 := netip.MustParsePrefix("2000::/3")
	sixToFour := netip.MustParsePrefix("2002::/16")
	teredo := netip.MustParsePrefix("2001::/32")
	for _, addr := range addrs {
		addr = addr.Unmap()
		if addr.Zone() != "" || routing.IsNonGlobal(addr) ||
			addr.Is6() && (!publicV6.Contains(addr) || sixToFour.Contains(addr) || teredo.Contains(addr)) {
			return fail(0, "non_public_address")
		}
	}
	ok(0, start)
	start = time.Now()
	dialer := net.Dialer{Timeout: 1200 * time.Millisecond}
	var conn net.Conn
	for _, addr := range addrs {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	if conn == nil {
		return fail(1, "connect_failed")
	}
	defer conn.Close()
	ok(1, start)
	sni := node.IngressSNI
	if sni == "" {
		sni = host
	}
	start = time.Now()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fail(2, "handshake_failed")
	}
	ok(2, start)
	return result
}

func CheckableNode(st *controlstore.Store, id string) (controlstore.Node, error) {
	nodes, err := st.ListNodes()
	if err != nil {
		return controlstore.Node{}, err
	}
	for _, node := range nodes {
		if node.ID == id && node.RevokedAt == nil {
			return node, nil
		}
	}
	return controlstore.Node{}, fmt.Errorf("VALIDATION_FAILED: unknown active node")
}
