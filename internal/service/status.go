package service

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"aravpn/core/health"
	"aravpn/core/limits"
	"aravpn/core/policy"
	"aravpn/core/routing"
)

// Topology is the configured exit set (server-pushed, signed in the real
// deployment; file-backed in this build and validated before use).
type Topology struct {
	SchemaVersion    int            `json:"schema_version"`
	Exits            []routing.Exit `json:"exits"`
	CurrentForeignID string         `json:"current_foreign_id"`
	AccessDown       bool           `json:"access_down"`
}

// LoadTopology reads and validates topology.json. Missing file yields the
// single-node minimal topology (RU exit only) so doctor/status work on a
// fresh install.
func (s *Service) LoadTopology() (Topology, error) {
	b, err := os.ReadFile(s.State.TopoPath())
	if os.IsNotExist(err) {
		return Topology{
			SchemaVersion: 1,
			Exits:         []routing.Exit{{ID: "ru-e", Country: "RU", Priority: 0, Role: routing.RoleRU}},
		}, nil
	}
	if err != nil {
		return Topology{}, err
	}
	var t Topology
	if err := json.Unmarshal(b, &t); err != nil {
		return Topology{}, fmt.Errorf("topology.json unreadable: %w", err)
	}
	if t.SchemaVersion != 1 {
		return Topology{}, fmt.Errorf("topology schema_version %d unsupported", t.SchemaVersion)
	}
	if err := routing.ValidateTopology(routing.Topology{Exits: t.Exits, CurrentForeignID: t.CurrentForeignID}); err != nil {
		return Topology{}, fmt.Errorf("POLICY_INVALID: %w", err)
	}
	return t, nil
}

// healthFileMaxAge bounds the whole snapshot file's freshness; it matches
// the documented probe interval (5 s) with generous jitter and lost-write
// tolerance.
const healthFileMaxAge = 30 * time.Second

// LoadHealthSnapshot reads the agent-written health snapshot. Freshness is
// enforced per observation, not only per file (review R10): one node being
// updated must not lend its freshness to hour-old observations of other
// nodes. Eligible-for-traffic states with stale, missing or future
// observation timestamps degrade to unknown; down/quarantined stay (they
// are safe directions of the contract).
func (s *Service) LoadHealthSnapshot() (routing.Snapshot, error) {
	out := routing.Snapshot{}
	b, err := os.ReadFile(s.State.HealthPath())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var raw struct {
		UpdatedAt time.Time                  `json:"updated_at"`
		Nodes     map[string]health.Snapshot `json:"nodes"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return out, fmt.Errorf("health.json unreadable: %w", err)
	}
	// A snapshot file older than the documented window is stale: nothing
	// in it may count as healthy (docs/FAILOVER.md).
	if time.Since(raw.UpdatedAt) > healthFileMaxAge {
		return out, nil
	}
	now := time.Now()
	for id, h := range raw.Nodes {
		st := h.State
		switch st {
		case health.Healthy, health.Recovering, health.Suspect:
			// eligibility-bearing states need a fresh observation
			age := now.Sub(h.LastObservation)
			if h.LastObservation.IsZero() || age < 0 || age > healthFileMaxAge {
				st = health.Unknown
			}
		case health.Down, health.Quarantined, health.Unknown:
			// safe or already non-eligible; keep as-is
		default:
			st = health.Unknown // unknown enum values are never eligible
		}
		out[id] = st
	}
	return out, nil
}

// LoadSystemACL returns the system ACL. In this build it is the secure
// default (deny non-global); administrator LAN exceptions arrive via the
// control plane.
func (s *Service) LoadSystemACL() policy.SystemACL {
	return policy.SystemACL{DenyNonGlobal: true}
}

// LoadPolicyStore returns the policy file store for the state dir.
func (s *Service) LoadPolicyStore() (*policy.Store, error) {
	return policy.NewStore(s.State.PolicyDir())
}

// StatusView is the single status object both UI and CLI render.
type StatusView struct {
	Mode           string     `json:"mode"`
	ExitID         string     `json:"exit_id,omitempty"`
	Country        string     `json:"country,omitempty"`
	Reason         string     `json:"reason_code"`
	PolicyRevision int64      `json:"policy_revision"`
	Generation     uint64     `json:"generation"`
	AccessDown     bool       `json:"access_down"`
	QuotaExhausted bool       `json:"quota_exhausted"`
	Topology       []NodeView `json:"topology"`
}

// NodeView is one node's row for status output.
type NodeView struct {
	ID       string `json:"id"`
	Country  string `json:"country"`
	Priority int    `json:"priority"`
	Role     string `json:"role"`
	Health   string `json:"health"`
}

// Status computes the current factual state. It makes no network requests:
// it reads the last health snapshot, exactly as documented.
func (s *Service) Status() (*StatusView, error) {
	topo, err := s.LoadTopology()
	if err != nil {
		return nil, err
	}
	hs, err := s.LoadHealthSnapshot()
	if err != nil {
		return nil, err
	}
	pol, err := s.LoadPolicyStore()
	if err != nil {
		return nil, err
	}
	p, err := pol.Load()
	if err != nil {
		return nil, err
	}
	quotaState, err := s.quotaExhausted()
	if err != nil {
		return nil, err
	}
	dec := routing.Decide(
		routing.Topology{Exits: topo.Exits, CurrentForeignID: topo.CurrentForeignID, AccessDown: topo.AccessDown},
		hs, p, s.LoadSystemACL(),
		policy.Destination{Domain: "status.example", Proto: policy.ProtoTCP, Port: 443},
		routing.QuotaState{Exhausted: quotaState}, 0,
	)
	view := &StatusView{
		Mode:           string(dec.Mode),
		ExitID:         dec.ExitID,
		Country:        dec.Country,
		Reason:         dec.Reason,
		PolicyRevision: p.Revision,
		AccessDown:     topo.AccessDown,
		QuotaExhausted: quotaState,
	}
	for _, e := range topo.Exits {
		h := hs[e.ID]
		if h == "" {
			h = health.Unknown
		}
		view.Topology = append(view.Topology, NodeView{
			ID: e.ID, Country: e.Country, Priority: e.Priority, Role: string(e.Role), Health: string(h),
		})
	}
	return view, nil
}

// RouteExplain explains the decision for one destination without any
// network request to it.
func (s *Service) RouteExplain(domain, ip, proto string, port int) (map[string]any, error) {
	topo, err := s.LoadTopology()
	if err != nil {
		return nil, err
	}
	hs, err := s.LoadHealthSnapshot()
	if err != nil {
		return nil, err
	}
	pol, err := s.LoadPolicyStore()
	if err != nil {
		return nil, err
	}
	p, err := pol.Load()
	if err != nil {
		return nil, err
	}
	d := policy.Destination{Proto: policy.Protocol(proto), Port: port}
	if domain != "" {
		c, err := policy.CanonicalDomain(domain)
		if err != nil {
			return nil, fmt.Errorf("VALIDATION_FAILED: %v", err)
		}
		d.Domain = c
	}
	if ip != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return nil, fmt.Errorf("VALIDATION_FAILED: %q is not an IP address", ip)
		}
		d.IP = a
	}
	quotaState, err := s.quotaExhausted()
	if err != nil {
		return nil, err
	}
	dec := routing.Decide(
		routing.Topology{Exits: topo.Exits, CurrentForeignID: topo.CurrentForeignID, AccessDown: topo.AccessDown},
		hs, p, s.LoadSystemACL(), d, routing.QuotaState{Exhausted: quotaState}, 0,
	)
	return dec.ExplainView(), nil
}

// quotaExhausted reads the AUTHORITATIVE shared state (review S05): the
// account scope {AccountID, DeviceID:""} reflects every device's spend,
// so exhaustion of the ACCOUNT by any device blocks all devices. Device
// scope exhaustion is additional. Either exhausted => data blocked.
func (s *Service) quotaExhausted() (bool, error) {
	cfg, err := s.LoadLimitsConfig()
	if err != nil {
		return false, err
	}
	if cfg.Device.TotalBytes == nil && cfg.Account.TotalBytes == nil {
		return false, nil
	}
	jr, err := limits.OpenFileJournal(s.State.LimitsDir())
	if err != nil {
		// journal unreadable: conservative — refuse data rather than
		// silently grant (docs/LIMITS_QUOTAS.md)
		return true, nil
	}
	now := time.Now().UTC()
	ledger, err := limits.NewQuotaLedger(cfg.AccountID, cfg.Account.TotalBytes, cfg.Period, jr, now)
	if err != nil {
		return true, nil
	}
	ledger.SetDeviceLimit(cfg.DeviceID, cfg.Device.TotalBytes)
	dev, err := ledger.DeviceTracker(cfg.DeviceID, now)
	if err != nil {
		return true, nil
	}
	if ledger.AccountState(now).Exhausted {
		return true, nil
	}
	return dev.Snapshot(now).Exhausted, nil
}
