// Package netplan models privileged network operations as typed, reviewed
// plans with an ownership scope and a per-step durable journal
// (docs/OPERATIONS.md, review R01).
//
// Ownership model: a plan must declare an OwnershipScope; every operation
// is validated against it before execution. A caller-set Owner label alone
// proves nothing — "ara" touching table main, the default route, or a host
// interface's qdisc is refused even when the plan claims the ARA owner.
// Execution records intent and result for EVERY step so a crash mid-apply
// leaves a durable trace and recovery can invert only completed steps,
// only on scope-owned objects — objects that may have existed before ARA
// are never deleted by a blanket cleanup.
package netplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// OpKind enumerates every operation the helper may perform. Anything not
// in this table is unrepresentable by construction.
type OpKind string

const (
	OpAddRoute    OpKind = "add_route"
	OpDelRoute    OpKind = "del_route"
	OpAddRule     OpKind = "add_rule" // policy routing rule (fwmark -> table)
	OpDelRule     OpKind = "del_rule"
	OpAddNftTable OpKind = "add_nft_table"
	OpDelNftTable OpKind = "del_nft_table"
	OpAddQdisc    OpKind = "add_qdisc" // owned qdisc on an ARA-owned device
	OpDelQdisc    OpKind = "del_qdisc"
)

// Op is one typed operation.
type Op struct {
	Kind     OpKind `json:"kind"`
	Owner    string `json:"owner"` // caller label; NOT proof of ownership
	Table    string `json:"table,omitempty"`
	Mark     uint32 `json:"mark,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Device   string `json:"device,omitempty"`
	Priority uint32 `json:"priority,omitempty"`
}

// Scope declares the trusted ownership area of one ARA installation: the
// exact objects the helper may create, modify or delete. Everything
// outside is foreign, regardless of the Owner label on an Op
// (review R01).
type Scope struct {
	Name string `json:"name"`
	// Interfaces are device names ARA created or was explicitly granted
	// (e.g. its own veth pair / TUN). Routes and qdiscs are restricted to
	// these; host interfaces such as eth0 can never appear.
	Interfaces []string `json:"interfaces"`
	// QdiscDevices is the subset of Interfaces where ARA owns the ROOT
	// qdisc. Root qdisc ownership is a separate grant: replacing the root
	// qdisc of a shared device would discard someone else's shaping.
	QdiscDevices []string `json:"qdisc_devices,omitempty"`
	// Tables are routing table names/IDs ARA owns (e.g. "52100").
	// Reserved system tables are refused at scope construction.
	Tables []string `json:"tables"`
	// Marks are fwmark values ARA owns for policy rules.
	Marks []uint32 `json:"marks"`
	// NftTables are full nftables table names ARA owns ("inet ara-filter").
	NftTables []string `json:"nft_tables"`
}

func (s *Scope) validate() error {
	if s == nil || s.Name == "" {
		return fmt.Errorf("ownership scope with a name is required")
	}
	for _, t := range s.Tables {
		if c, ok := canonicalTable(t); ok && reservedTables[c] {
			return fmt.Errorf("scope %s: table %q is a reserved system table and cannot be owned", s.Name, t)
		}
	}
	for _, d := range s.QdiscDevices {
		if !s.hasInterface(d) {
			return fmt.Errorf("scope %s: qdisc device %q is not in Interfaces", s.Name, d)
		}
	}
	return nil
}

// canonicalTable reduces every accepted spelling of a routing table to
// one comparison key: decimal and hex IDs map to "id:<n>", names to
// "name:<lower>", so "main", "0xfe"→not-a-name and numeric aliases
// cannot bypass the reserved list through their spelling (review S01).
func canonicalTable(t string) (string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return "", false
	}
	if n, err := strconv.ParseUint(t, 10, 32); err == nil {
		return fmt.Sprintf("id:%d", n), true
	}
	if strings.HasPrefix(t, "0x") {
		if n, err := strconv.ParseUint(t[2:], 16, 32); err == nil {
			return fmt.Sprintf("id:%d", n), true
		}
	}
	return "name:" + t, true
}

// reservedTables covers the well-known system tables by name and numeric
// ID (Linux: default=253, main=254, local=255; 0 = unspec).
var reservedTables = map[string]bool{
	"name:main": true, "name:local": true, "name:default": true,
	"id:0": true, "id:253": true, "id:254": true, "id:255": true,
}

func (s *Scope) hasTable(name string) bool {
	c, ok := canonicalTable(name)
	if !ok {
		return false
	}
	for _, t := range s.Tables {
		if ct, ok2 := canonicalTable(t); ok2 && ct == c {
			return true
		}
	}
	return false
}

func (s *Scope) hasInterface(name string) bool {
	for _, i := range s.Interfaces {
		if i == name {
			return true
		}
	}
	return false
}

func (s *Scope) hasQdiscDevice(name string) bool {
	for _, i := range s.QdiscDevices {
		if i == name {
			return true
		}
	}
	return false
}

func (s *Scope) hasMark(mark uint32) bool {
	for _, m := range s.Marks {
		if m == mark {
			return true
		}
	}
	return false
}

func (s *Scope) hasNftTable(name string) bool {
	for _, t := range s.NftTables {
		if t == name {
			return true
		}
	}
	return false
}

// Route authority model (review S01): every route operation MUST carry an
// explicit table, and that table must belong to the ownership scope. A
// route without "table" would land in the host main table, which can never
// be ARA-owned, so the empty form is refused outright. A default route
// (0.0.0.0/0, ::/0) inside a genuinely ARA-owned table is a different
// authority from the host's default route and stays permitted there; the
// host main table remains unreachable because reserved tables are refused
// in every scope.
func (o Op) Validate() error {
	switch o.Kind {
	case OpAddRoute, OpDelRoute:
		p, err := netip.ParsePrefix(o.Prefix)
		if err != nil {
			return fmt.Errorf("route: bad prefix %q", o.Prefix)
		}
		_ = p
		if strings.TrimSpace(o.Table) == "" {
			return fmt.Errorf("route: explicit table is required; a route without one targets the host main table, which ARA never owns")
		}
		if o.Gateway != "" {
			if _, err := netip.ParseAddr(o.Gateway); err != nil {
				return fmt.Errorf("route: bad gateway %q", o.Gateway)
			}
		}
		if o.Device == "" {
			return fmt.Errorf("route: device required")
		}
	case OpAddRule, OpDelRule:
		if o.Mark == 0 {
			return fmt.Errorf("rule: mark required")
		}
		if o.Table == "" {
			return fmt.Errorf("rule: table required")
		}
	case OpAddNftTable, OpDelNftTable:
		if o.Table == "" {
			return fmt.Errorf("nft table name required")
		}
	case OpAddQdisc, OpDelQdisc:
		if o.Device == "" {
			return fmt.Errorf("qdisc: device required")
		}
	default:
		return fmt.Errorf("unknown op kind %q", o.Kind)
	}
	return nil
}

// validateAgainstScope enforces the ownership area (review R01). It is
// called for every op before any command runs; the Owner label alone
// grants nothing.
func (o Op) validateAgainstScope(s *Scope) error {
	if err := o.Validate(); err != nil {
		return err
	}
	switch o.Kind {
	case OpAddRoute, OpDelRoute:
		if !s.hasInterface(o.Device) {
			return fmt.Errorf("route to %s: device %q is outside the ownership scope %s", o.Prefix, o.Device, s.Name)
		}
		// explicit table is enforced by Op.Validate; canonical comparison
		// means "52100" and "0xCB64" resolve to the same ownership entry
		if !s.hasTable(o.Table) {
			return fmt.Errorf("route: table %q is outside the ownership scope %s", o.Table, s.Name)
		}
	case OpAddRule, OpDelRule:
		if !s.hasMark(o.Mark) {
			return fmt.Errorf("rule: fwmark %d is outside the ownership scope %s", o.Mark, s.Name)
		}
		if !s.hasTable(o.Table) {
			return fmt.Errorf("rule: table %q is outside the ownership scope %s", o.Table, s.Name)
		}
	case OpAddNftTable, OpDelNftTable:
		if !s.hasNftTable(o.Table) {
			return fmt.Errorf("nft table %q is outside the ownership scope %s", o.Table, s.Name)
		}
	case OpAddQdisc, OpDelQdisc:
		if !s.hasQdiscDevice(o.Device) {
			return fmt.Errorf("qdisc: device %q is not granted root-qdisc ownership in scope %s", o.Device, s.Name)
		}
	}
	return nil
}

// Plan is an ordered set of ops with its inverse for rollback. A plan
// without a declared Scope is invalid: unscoped plans touch nothing.
// Hash is the content hash recorded with plan_begin and re-verified by
// recovery: a journaled plan that no longer matches its hash is refused
// rather than blindly undone (review S02/S03).
type Plan struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	Scope     *Scope    `json:"scope,omitempty"`
	Ops       []Op      `json:"ops"`
	Hash      string    `json:"hash,omitempty"`
}

// ContentHash computes the deterministic hash of the plan content with
// the Hash field excluded (so the stored hash cannot cover itself).
func (p *Plan) ContentHash() (string, error) {
	cp := *p
	cp.Hash = ""
	b, err := json.Marshal(&cp)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Validate checks structure and ownership. Without a scope every
// operation is refused: the ability to declare an owner string is not
// the ability to own host objects (review R01 evidence: add_route to
// 0.0.0.0/0 via eth0 with table main was accepted on the Owner label
// alone).
func (p *Plan) Validate() error {
	if p.Owner == "" {
		return fmt.Errorf("plan owner required")
	}
	if len(p.Ops) == 0 {
		return fmt.Errorf("empty plan")
	}
	if err := p.Scope.validate(); err != nil {
		return fmt.Errorf("plan ownership: %w", err)
	}
	for i := range p.Ops {
		if p.Ops[i].Owner != p.Owner {
			return fmt.Errorf("op[%d] owner %q does not match plan owner %q", i, p.Ops[i].Owner, p.Owner)
		}
		if err := p.Ops[i].validateAgainstScope(p.Scope); err != nil {
			return fmt.Errorf("op[%d]: %w", i, err)
		}
	}
	return nil
}

// Invert returns the rollback plan (reversed ops with inverse kinds).
// Rollback only inverts adds owned by the scope; deletes are never
// "restored" because re-creating a deleted foreign object is impossible
// to do safely from a journal.
func (p *Plan) Invert() *Plan {
	out := &Plan{ID: p.ID + "-rollback", Owner: p.Owner, CreatedAt: time.Now().UTC(), Scope: p.Scope}
	for i := len(p.Ops) - 1; i >= 0; i-- {
		o := p.Ops[i]
		switch o.Kind {
		case OpAddRoute:
			o.Kind = OpDelRoute
		case OpAddRule:
			o.Kind = OpDelRule
		case OpAddNftTable:
			o.Kind = OpDelNftTable
		case OpAddQdisc:
			o.Kind = OpDelQdisc
		default:
			continue
		}
		out.Ops = append(out.Ops, o)
	}
	return out
}

// currentTime is split out for test determinism.
func currentTime() time.Time { return time.Now().UTC() }
