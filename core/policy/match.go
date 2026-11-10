package policy

import (
	"net/netip"
)

// Destination is what is known about one connection attempt. A flow carries
// a domain only when its provenance is trusted (explicit proxy hostname or
// scoped fake-IP association, docs/ROUTING_DNS.md); otherwise Domain is
// empty and domain conditions cannot match. IP may also be empty for
// domain-only preview before resolution.
type Destination struct {
	Domain string // canonical form
	IP     netip.Addr
	Proto  Protocol
	Port   int
}

// MatchResult reports whether the rule matched and, when it did not, which
// condition family was unsatisfied (used by route explain).
type MatchResult struct {
	Matched       bool
	FailedSection string // "domain_exact" | "domain_suffix" | "cidr" | "transport"
}

func (r *Rule) Match(d Destination) MatchResult {
	if !r.Enabled {
		return MatchResult{Matched: false, FailedSection: "disabled"}
	}
	if len(r.DomainExact) > 0 {
		if d.Domain == "" {
			return MatchResult{false, "domain_exact"}
		}
		ok := false
		for _, m := range r.DomainExact {
			if d.Domain == m {
				ok = true
				break
			}
		}
		if !ok {
			return MatchResult{false, "domain_exact"}
		}
	}
	if len(r.DomainSuffix) > 0 {
		if d.Domain == "" {
			return MatchResult{false, "domain_suffix"}
		}
		ok := false
		for _, m := range r.DomainSuffix {
			if MatchesSuffix(d.Domain, m) {
				ok = true
				break
			}
		}
		if !ok {
			return MatchResult{false, "domain_suffix"}
		}
	}
	if len(r.CIDR) > 0 {
		if !d.IP.IsValid() {
			return MatchResult{false, "cidr"}
		}
		ok := false
		for _, c := range r.CIDR {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				continue // unreachable after Validate; defensive
			}
			if p.Contains(d.IP) {
				ok = true
				break
			}
		}
		if !ok {
			return MatchResult{false, "cidr"}
		}
	}
	if r.Proto != ProtoAny {
		if d.Proto != r.Proto {
			return MatchResult{false, "transport"}
		}
	}
	if len(r.Ports) > 0 {
		ok := false
		for _, pr := range r.Ports {
			if d.Port >= pr.From && d.Port <= pr.To {
				ok = true
				break
			}
		}
		if !ok {
			return MatchResult{false, "transport"}
		}
	}
	return MatchResult{Matched: true}
}

// Evaluated is the outcome of evaluating a policy against one destination.
type Evaluated struct {
	MatchedRuleID string // empty => default action
	Action        Action
	ExitID        string
	// AllowRUFallback resolves rule-level override against the profile
	// default. Only meaningful when Action == FOREIGN_POOL.
	AllowRUFallback bool
	// ExplicitFallbackOverride is true when a matched rule carried its
	// own allow_ru_fallback value rather than inheriting the profile
	// default; routing uses it to produce a distinct reason code.
	ExplicitFallbackOverride bool
}

// Evaluate applies user rules in stored array order (first match wins,
// no hidden sorting) and returns the desired action. Order of the Rules
// slice is significant and preserved by the store.
func (p *Policy) Evaluate(d Destination) Evaluated {
	for i := range p.Rules {
		if m := p.Rules[i].Match(d); m.Matched {
			r := &p.Rules[i]
			allow := p.AllowRUFallback
			explicit := false
			if r.AllowRUFallback != nil {
				allow = *r.AllowRUFallback
				explicit = true
			}
			if r.Action == ActionForeignExit {
				allow = false
			}
			return Evaluated{
				MatchedRuleID:            r.ID,
				Action:                   r.Action,
				ExitID:                   r.ExitID,
				AllowRUFallback:          allow,
				ExplicitFallbackOverride: explicit,
			}
		}
	}
	if p.DefaultAction == ActionForeignExit {
		return Evaluated{Action: ActionForeignExit, ExitID: p.DefaultExitID}
	}
	if p.DefaultAction == ActionBlock {
		return Evaluated{Action: ActionBlock}
	}
	if p.DefaultAction == ActionRUExit {
		return Evaluated{Action: ActionRUExit}
	}
	return Evaluated{Action: ActionForeignPool, AllowRUFallback: p.AllowRUFallback}
}
