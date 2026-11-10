// Package policy implements the ARA policy IR: domain/CIDR/transport rules,
// full-document validation, first-match evaluation and an LKG file store.
//
// The IR is OS-independent and is the single source of truth compiled into
// both client-side domain decisions and Edge-side server ACL checks
// (docs/ROUTING_DNS.md). Engine-specific configs (Xray/sing-box) are derived
// artifacts and never parsed back as product policy.
package policy

import (
	"fmt"
	"net/netip"
	"strings"
)

// Action is the routing decision for a matched rule.
type Action string

const (
	ActionRUExit      Action = "RU_EXIT"
	ActionForeignPool Action = "FOREIGN_POOL"
	ActionForeignExit Action = "FOREIGN_EXIT"
	ActionBlock       Action = "BLOCK"
	// ActionDirect (B39): explicit client-side DIRECT — matched traffic
	// bypasses the VPN tunnel through the host's own network with its own
	// DNS scope. It is a distinct, explicitly configured routing decision,
	// never an automatic fallback of RU/foreign/Edge failures.
	ActionDirect Action = "DIRECT"
)

func (a Action) Valid() bool {
	switch a {
	case ActionRUExit, ActionForeignPool, ActionForeignExit, ActionBlock, ActionDirect:
		return true
	}
	return false
}

// Protocol constrains a rule to one transport. Empty means both.
type Protocol string

const (
	ProtoAny Protocol = ""
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

func (p Protocol) Valid() bool {
	switch p {
	case ProtoAny, ProtoTCP, ProtoUDP:
		return true
	}
	return false
}

// PortRange is an inclusive TCP/UDP port range. Single ports use From==To.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Rule is one ordered user rule. Lists inside one match type are OR;
// different match types present on the same rule are AND
// (docs/ROUTING_DNS.md). A rule with no match conditions is invalid.
type Rule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`

	DomainExact  []string    `json:"domain_exact,omitempty"`
	DomainSuffix []string    `json:"domain_suffix,omitempty"`
	CIDR         []string    `json:"cidr,omitempty"`
	Proto        Protocol    `json:"proto,omitempty"`
	Ports        []PortRange `json:"ports,omitempty"`

	Action          Action `json:"action"`
	ExitID          string `json:"exit_id,omitempty"`
	AllowRUFallback *bool  `json:"allow_ru_fallback,omitempty"` // nil => profile default; only meaningful for FOREIGN_POOL
}

// ExitFallback controls new connections when a named foreign exit is unavailable.
type ExitFallback string

const (
	ExitFallbackBlock         ExitFallback = "block"
	ExitFallbackRU            ExitFallback = "ru"
	ExitFallbackForeign       ExitFallback = "foreign"
	ExitFallbackForeignThenRU ExitFallback = "foreign_then_ru"
)

// Policy is a complete policy document. Validation is whole-document:
// any invalid member rejects the entire import (no partial acceptance).
type Policy struct {
	SchemaVersion       int          `json:"schema_version"`
	Revision            int64        `json:"revision"`
	AllowRUFallback     bool         `json:"allow_ru_fallback"`
	DefaultAction       Action       `json:"default_action,omitempty"`
	DefaultExitID       string       `json:"default_exit_id,omitempty"`
	ForeignExitFallback ExitFallback `json:"foreign_exit_fallback,omitempty"`
	Rules               []Rule       `json:"rules"`
}

// SystemACL is the layer evaluated before any user rule. It is not
// editable through the site rule editor (bootstrap exclusions are managed
// separately, docs/ROUTING_DNS.md).
type SystemACL struct {
	// DenyNonGlobal blocks loopback, private, link-local, multicast,
	// unspecified and cloud-metadata destinations for user proxy traffic.
	DenyNonGlobal bool `json:"deny_non_global"`
	// LANExceptions re-enables explicitly listed CIDRs; only an
	// administrator policy may set them, separately from Internet rules.
	LANExceptions []string `json:"lan_exceptions,omitempty"`
}

func (s SystemACL) Validate() error {
	for _, c := range s.LANExceptions {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("lan exception %q: %w", c, err)
		}
		if !p.Addr().Is4() && !p.Addr().Is6() {
			return fmt.Errorf("lan exception %q: unsupported address family", c)
		}
	}
	return nil
}

// ParsePortRange parses "443" or "1000-2000".
func ParsePortRange(s string) (PortRange, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		var p int
		if _, err := fmt.Sscanf(s, "%d", &p); err != nil {
			return PortRange{}, fmt.Errorf("port %q: not a number", s)
		}
		if p < 1 || p > 65535 {
			return PortRange{}, fmt.Errorf("port %d: out of range 1..65535", p)
		}
		return PortRange{From: p, To: p}, nil
	}
	var from, to int
	if _, err := fmt.Sscanf(lo, "%d", &from); err != nil {
		return PortRange{}, fmt.Errorf("port range %q: bad lower bound", s)
	}
	if _, err := fmt.Sscanf(hi, "%d", &to); err != nil {
		return PortRange{}, fmt.Errorf("port range %q: bad upper bound", s)
	}
	if from < 1 || to > 65535 || from > to {
		return PortRange{}, fmt.Errorf("port range %q: must be 1..65535 with from<=to", s)
	}
	return PortRange{From: from, To: to}, nil
}
