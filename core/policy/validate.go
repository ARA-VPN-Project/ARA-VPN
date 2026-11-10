package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Validate checks the whole document. The first error fails the entire
// policy; callers must keep the last-known-good document.
func (p *Policy) Validate() error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d: only 1 is supported by this build", p.SchemaVersion)
	}
	if p.Revision < 0 {
		return fmt.Errorf("revision %d: must be non-negative", p.Revision)
	}
	if p.DefaultAction != "" && p.DefaultAction != ActionRUExit && p.DefaultAction != ActionForeignPool && p.DefaultAction != ActionForeignExit && p.DefaultAction != ActionBlock {
		return fmt.Errorf("default_action must be RU_EXIT, FOREIGN_POOL, FOREIGN_EXIT or BLOCK")
	}
	if p.DefaultAction == ActionForeignExit {
		if p.DefaultExitID == "" || strings.TrimSpace(p.DefaultExitID) != p.DefaultExitID {
			return fmt.Errorf("default_action FOREIGN_EXIT requires default_exit_id")
		}
	} else if p.DefaultExitID != "" {
		return fmt.Errorf("default_exit_id is only valid with default_action FOREIGN_EXIT")
	}
	switch p.ForeignExitFallback {
	case "", ExitFallbackBlock, ExitFallbackRU, ExitFallbackForeign, ExitFallbackForeignThenRU:
	default:
		return fmt.Errorf("invalid foreign_exit_fallback %q", p.ForeignExitFallback)
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule[%d]: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

// Validate checks one rule: condition and action completeness, canonical
// domains, strict CIDR parsing, port bounds. No network access occurs.
func (r *Rule) Validate() error {
	if !r.Action.Valid() {
		return fmt.Errorf("action %q: must be RU_EXIT, FOREIGN_POOL, FOREIGN_EXIT, DIRECT or BLOCK", r.Action)
	}
	if r.Action == ActionForeignExit {
		if r.ExitID == "" || strings.TrimSpace(r.ExitID) != r.ExitID {
			return fmt.Errorf("FOREIGN_EXIT requires an exit_id")
		}
	} else if r.ExitID != "" {
		return fmt.Errorf("exit_id is only valid with action FOREIGN_EXIT")
	}
	if !r.Proto.Valid() {
		return fmt.Errorf("proto %q: must be tcp, udp or empty", r.Proto)
	}
	if r.AllowRUFallback != nil && r.Action != ActionForeignPool {
		return fmt.Errorf("allow_ru_fallback is only valid with action FOREIGN_POOL")
	}
	hasCondition := false
	for _, d := range r.DomainExact {
		c, err := CanonicalDomain(d)
		if err != nil {
			return fmt.Errorf("domain_exact %q: %w", d, err)
		}
		if !IsCanonical(d) {
			return fmt.Errorf("domain_exact %q: must be stored canonical (%q); normalize before saving", d, c)
		}
		hasCondition = true
	}
	for _, d := range r.DomainSuffix {
		c, err := CanonicalDomain(d)
		if err != nil {
			return fmt.Errorf("domain_suffix %q: %w", d, err)
		}
		if !IsCanonical(d) {
			return fmt.Errorf("domain_suffix %q: must be stored canonical (%q)", d, c)
		}
		hasCondition = true
	}
	for _, c := range r.CIDR {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("cidr %q: %w", c, err)
		}
		// Store CIDRs in masked form only; "203.0.113.7/24" is ambiguous
		// author intent and would hide a typo in the rule editor.
		if p != p.Masked() {
			return fmt.Errorf("cidr %q: host bits must not be set; write %q", c, p.Masked())
		}
		hasCondition = true
	}
	for i, pr := range r.Ports {
		if pr.From < 1 || pr.To > 65535 || pr.From > pr.To {
			return fmt.Errorf("ports[%d] %d-%d: must be 1..65535 with from<=to", i, pr.From, pr.To)
		}
		hasCondition = true
	}
	if !hasCondition {
		return fmt.Errorf("rule has no match conditions; a catch-all is expressed by the default action, not a rule")
	}
	if len(r.Ports) > 0 && r.Proto == ProtoAny {
		return fmt.Errorf("ports require proto tcp or udp")
	}
	return nil
}

// NormalizeDomains canonicalizes all domain values in place. It is applied
// before Validate by ingestion paths that accept user-typed input (UI
// editor, CLI import from human files).
func (p *Policy) NormalizeDomains() error {
	for i := range p.Rules {
		r := &p.Rules[i]
		for j, d := range r.DomainExact {
			c, err := CanonicalDomain(d)
			if err != nil {
				return fmt.Errorf("rule %s domain_exact %q: %w", r.ID, d, err)
			}
			r.DomainExact[j] = c
		}
		for j, d := range r.DomainSuffix {
			c, err := CanonicalDomain(d)
			if err != nil {
				return fmt.Errorf("rule %s domain_suffix %q: %w", r.ID, d, err)
			}
			r.DomainSuffix[j] = c
		}
		sort.Strings(r.DomainExact)
		sort.Strings(r.DomainSuffix)
	}
	return nil
}
