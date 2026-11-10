// Package capability models the negotiated feature set between ARA
// components (docs/ARCHITECTURE.md): nodes advertise capabilities, control
// never sends a transport the target does not support, and unsupported
// requests fail with a typed error instead of a best-effort imitation.
package capability

import (
	"fmt"
	"sort"
	"strings"
)

// Well-known capability keys.
const (
	CapTUN              = "tun"
	CapProxyInbound     = "proxy_inbound"
	CapTransportXHTTP   = "transport.xhttp"
	CapTransportREALITY = "transport.reality"
	CapTransportWG      = "transport.wireguard"
	CapIPv6             = "ipv6"
	CapEmbeddedEngine   = "embedded_engine"
	CapRateLimiter      = "rate_limiter"
	CapQUOTA            = "quota"
)

// Set is a capability advertisement: name -> version/constraint string.
// A missing key means "not supported"; the empty version value means
// "supported, unconstrained".
type Set map[string]string

// Require verifies every requirement is advertised. Returns a typed error
// naming the first missing capability so callers can surface
// UNSUPPORTED_CAPABILITY with stable params.
func (s Set) Require(required Set) error {
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ver, ok := s[name]
		if !ok {
			return &UnsupportedError{Capability: name}
		}
		if req := required[name]; req != "" && ver != "" && ver != req {
			return &UnsupportedError{Capability: name, Need: req, Have: ver}
		}
	}
	return nil
}

// UnsupportedError is the typed negotiation failure.
type UnsupportedError struct {
	Capability string
	Need       string
	Have       string
}

func (e *UnsupportedError) Error() string {
	if e.Need == "" {
		return fmt.Sprintf("UNSUPPORTED_CAPABILITY: %s is not available on this node", e.Capability)
	}
	return fmt.Sprintf("UNSUPPORTED_CAPABILITY: %s needs version %s, node advertises %s", e.Capability, e.Need, e.Have)
}

// Common returns the intersection of two sets (useful for negotiation
// diagnostics and explain output).
func Common(a, b Set) Set {
	out := Set{}
	for name, ver := range a {
		if bver, ok := b[name]; ok && bver == ver {
			out[name] = ver
		}
	}
	return out
}

// Render returns a stable sorted "name=version" string for logs/status.
func (s Set) Render() string {
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		if s[n] == "" {
			parts = append(parts, n)
		} else {
			parts = append(parts, n+"@"+s[n])
		}
	}
	return strings.Join(parts, ",")
}
