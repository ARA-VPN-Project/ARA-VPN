package service

// Setup-from-file (docs/CLI_AUTOMATION.md): one setup.json may carry the
// client profile, the routing policy and the limits. validate → plan →
// apply → postcheck; the plan discipline (hash, expiry, preconditions,
// idempotent apply) wraps policy+limits through their existing stores and
// the profile lands in <state>/profiles/<name>.json (0600).

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/plan"
	"aravpn/core/policy"
	"aravpn/internal/txlog"
)

// SetupDoc is the on-disk setup request. Every section is optional; an
// empty document is a validation error (nothing to do must be explicit).
type SetupDoc struct {
	ProfileName string             `json:"profile_name,omitempty"`
	Profile     *SetupClientProfile `json:"profile,omitempty"`
	Policy      *policy.Policy      `json:"policy,omitempty"`
	Limits      *LimitsConfig       `json:"limits,omitempty"`
}

// SetupClientProfile mirrors clientengine.Profile without importing it
// (the service layer stays engine-agnostic; validation happens on use).
// Protocol is the Client→Edge ingress protocol ("" / "vless" in this
// build); it is independent of any Edge→Exit transit choice.
type SetupClientProfile struct {
	EnginePath string `json:"engine_path"`
	ServerAddr string `json:"server_addr"`
	ServerName string `json:"server_name"`
	CAPath     string `json:"ca_path"`
	UUID       string `json:"uuid"`
	// Ingress protocol; only vless is implemented (UNSUPPORTED_CAPABILITY
	// otherwise, validated on use).
	Protocol  string `json:"protocol,omitempty"`
	TUNName   string `json:"tun_name"`
	TUNAddr4  string `json:"tun_addr4"`
	TUNAddr6  string `json:"tun_addr6,omitempty"`
	MTU       int    `json:"mtu"`
	DNSServer string `json:"dns_server,omitempty"`
	WaitMode  string `json:"wait_mode,omitempty"`
}

// Validate checks the document is well-formed and non-empty.
func (d *SetupDoc) Validate() error {
	if d.Profile == nil && d.Policy == nil && d.Limits == nil {
		return fmt.Errorf("setup: at least one of profile, policy, limits is required")
	}
	if (d.Profile == nil) != (d.ProfileName == "") {
		return fmt.Errorf("setup: profile and profile_name must be set together")
	}
	// B16: profile names are owned-state identifiers — reject path escapes
	// before any write plan is staged.
	if err := validateOwnedStateName(d.ProfileName); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if d.Profile != nil {
		if d.Profile.EnginePath == "" || d.Profile.ServerAddr == "" || d.Profile.ServerName == "" ||
			d.Profile.CAPath == "" || d.Profile.UUID == "" || d.Profile.TUNName == "" || d.Profile.TUNAddr4 == "" {
			return fmt.Errorf("setup: profile is missing required fields")
		}
		if _, _, err := netSplitHostPort(d.Profile.ServerAddr); err != nil {
			return fmt.Errorf("setup: profile server_addr: %w", err)
		}
	}
	if d.Policy != nil {
		if err := d.Policy.Validate(); err != nil {
			return fmt.Errorf("POLICY_INVALID: %w", err)
		}
	}
	if d.Limits != nil {
		if err := d.Limits.Validate(); err != nil {
			return fmt.Errorf("setup: limits: %w", err)
		}
	}
	return nil
}

// setupChanges is the hashed plan payload.
type setupChanges struct {
	ProfileName string              `json:"profile_name,omitempty"`
	Profile     *SetupClientProfile `json:"profile,omitempty"`
	Policy      *policy.Policy      `json:"policy,omitempty"`
	Limits      *LimitsConfig       `json:"limits,omitempty"`
}

// SetupPlan validates the document and stages a composite plan whose hash
// covers every included section. Preconditions pin the current policy
// revision; expiry uses the shared plan TTL.
func (s *Service) SetupPlan(doc *SetupDoc, now time.Time) (*plan.Plan, string, error) {
	if err := doc.Validate(); err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: %w", err)
	}
	pre := map[string]string{}
	if doc.Policy != nil {
		store, err := s.LoadPolicyStore()
		if err != nil {
			return nil, "", err
		}
		cur, err := store.Load()
		if err != nil {
			return nil, "", err
		}
		pre["policy.revision"] = fmt.Sprint(cur.Revision)
	}
	ch, err := json.Marshal(setupChanges{
		ProfileName: doc.ProfileName, Profile: doc.Profile,
		Policy: doc.Policy, Limits: doc.Limits,
	})
	if err != nil {
		return nil, "", err
	}
	p := &plan.Plan{
		ID:             NewPlanID("setup"),
		Kind:           "setup",
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(plan.DefaultTTL),
		Preconditions:  pre,
		Changes:        ch,
		IdempotencyKey: NewPlanID("idem"),
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, "", err
	}
	reg, err := s.planRegistry()
	if err != nil {
		return nil, "", err
	}
	if _, err := reg.Stage(p); err != nil {
		return nil, "", err
	}
	if err := reg.Save(p); err != nil {
		return nil, "", err
	}
	return p, hash, nil
}

// SetupApply applies a staged setup plan: policy through the accepted
// store (CAS by the pinned revision), limits through the limits identity
// state, profile into profiles/<name>.json. Idempotent via the plan
// registry; every section application is logged to its tx trail.
func (s *Service) SetupApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	res, err := reg.Apply(planID, hash, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// setupExecutor adapts SetupApply to the plan registry.
type setupExecutor struct{ svc *Service }

func (e *setupExecutor) Kind() string { return "setup" }

func (e *setupExecutor) Check(p *plan.Plan, now time.Time) error {
	var ch setupChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return fmt.Errorf("setup changes: %w", err)
	}
	doc := SetupDoc{ProfileName: ch.ProfileName, Profile: ch.Profile, Policy: ch.Policy, Limits: ch.Limits}
	if err := doc.Validate(); err != nil {
		return err
	}
	// B18: the staged plan pinned the policy revision it was computed
	// from; a newer live revision is a typed conflict — never overwrite.
	if ch.Policy != nil {
		store, err := e.svc.LoadPolicyStore()
		if err != nil {
			return err
		}
		cur, err := store.Load()
		if err != nil {
			return err
		}
		if want := p.Preconditions["policy.revision"]; want != "" {
			if fmt.Sprint(cur.Revision) != want {
				return fmt.Errorf("CONFLICT: policy revision moved (plan pinned %s, current %d)", want, cur.Revision)
			}
		}
	}
	return nil
}

func (e *setupExecutor) RecognizeAlreadyApplied(p *plan.Plan) (plan.Result, bool) {
	return plan.Result{}, false
}

func (e *setupExecutor) Apply(p *plan.Plan, now time.Time) (plan.Result, error) {
	if err := e.svc.applySetupChanges(p, now); err != nil {
		return plan.Result{}, err
	}
	return plan.Result{Applied: true, Summary: map[string]string{"plan_id": p.ID}}, nil
}

// applySetupChanges is the registered executor body for kind "setup".
// The whole check→effect sequence runs under the state directory lock and
// every touched part keeps its real LKG: on any late failure the previous
// bytes are restored DURABLY (a compensation delete would destroy a
// working profile — product-completion B17). Limits go through the
// canonical limits state transaction (intent → commit → applied marker,
// identity = the setup plan), not a parallel side file.
func (s *Service) applySetupChanges(p *plan.Plan, now time.Time) error {
	var ch setupChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return fmt.Errorf("setup changes: %w", err)
	}
	release, err := policy.LockDir(s.State.Root)
	if err != nil {
		return fmt.Errorf("setup state lock: %w", err)
	}
	defer release()

	// B18 re-check INSIDE the serialization: the pinned policy revision
	// must still be current when the effects run (the policy CAS below is
	// the final authority; this makes the rejection happen before any
	// state change).
	var policyPath string
	if ch.Policy != nil {
		store, err := s.LoadPolicyStore()
		if err != nil {
			return err
		}
		cur, err := store.Load()
		if err != nil {
			return err
		}
		if want := p.Preconditions["policy.revision"]; want != "" {
			if fmt.Sprint(cur.Revision) != want {
				return fmt.Errorf("CONFLICT: policy revision moved (plan pinned %s, current %d)", want, cur.Revision)
			}
		}
		policyPath = filepath.Join(s.State.PolicyDir(), "policy.current.json")
	}

	// real LKG snapshot of every part this setup may change
	type lkg struct {
		path    string
		data    []byte
		existed bool
	}
	var lgks []lkg
	snapshot := func(path string) error {
		b, rerr := os.ReadFile(path)
		if os.IsNotExist(rerr) {
			lgks = append(lgks, lkg{path: path})
			return nil
		}
		if rerr != nil {
			return rerr
		}
		lgks = append(lgks, lkg{path: path, data: b, existed: true})
		return nil
	}
	profilePath := ""
	var profileBytes []byte
	if ch.Profile != nil {
		if err := validateOwnedStateName(ch.ProfileName); err != nil {
			return fmt.Errorf("setup: %w", err)
		}
		dir := filepath.Join(s.State.Root, "profiles")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		b, merr := json.MarshalIndent(ch.Profile, "", "  ")
		if merr != nil {
			return merr
		}
		profilePath = filepath.Join(dir, ch.ProfileName+".json")
		profileBytes = append(b, '\n')
		if err := snapshot(profilePath); err != nil {
			return err
		}
	}
	if ch.Limits != nil {
		if err := snapshot(s.State.LimitsPath()); err != nil {
			return err
		}
	}
	if ch.Policy != nil {
		if err := snapshot(policyPath); err != nil {
			return err
		}
	}
	// durable restore of every already-touched part, reverse order; the
	// returned error keeps the original cause and any restore failure
	restore := func(cause error) error {
		for i := len(lgks) - 1; i >= 0; i-- {
			l := lgks[i]
			if !l.existed {
				if rerr := os.Remove(l.path); rerr != nil && !os.IsNotExist(rerr) {
					return fmt.Errorf("%v; LKG restore (%s) failed: %w", cause, l.path, rerr)
				}
				continue
			}
			if rerr := DurableFileWrite(l.path, l.data); rerr != nil {
				return fmt.Errorf("%v; LKG restore (%s) failed: %w", cause, l.path, rerr)
			}
		}
		return cause
	}

	// effect 1: client profile (its own failure touches nothing else)
	if ch.Profile != nil {
		if err := DurableFileWrite(profilePath, profileBytes); err != nil {
			return restore(fmt.Errorf("profile: %w", err))
		}
	}
	// effect 2: limits — the authoritative canonical state transaction
	// (dir lock is held; intent and applied markers like LimitsApply)
	if ch.Limits != nil {
		if err := ch.Limits.Validate(); err != nil {
			return restore(fmt.Errorf("limits: %w", err))
		}
		lg, lerr := txlog.Open(filepath.Join(s.State.Root, "limits.txlog.jsonl"))
		if lerr != nil {
			return restore(fmt.Errorf("limits txlog open: %w", lerr))
		}
		if err := lg.Append(limitsTx{Kind: limitsTxApply, PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, Config: *ch.Limits}); err != nil {
			return restore(fmt.Errorf("limits txlog intent write failed: %w", err))
		}
		id := &limitsIdentity{PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, AppliedAt: now.UTC()}
		if err := s.commitLimitsState(ch.Limits, id); err != nil {
			return restore(fmt.Errorf("limits: %w", err))
		}
		if err := lg.Append(limitsTx{Kind: "applied", PlanID: p.ID, IdempotencyKey: p.IdempotencyKey, Config: *ch.Limits}); err != nil {
			return restore(fmt.Errorf("limits applied but outcome marker not recorded: %w", err))
		}
	}
	// effect 3: policy CAS last (B17 ordering), under the pinned revision
	if ch.Policy != nil {
		store, err := s.LoadPolicyStore()
		if err != nil {
			return restore(err)
		}
		cur, err := store.Load()
		if err != nil {
			return restore(err)
		}
		cand := *ch.Policy
		cand.Revision = cur.Revision + 1
		if _, err := store.ValidateAndApplyIdentity(&cand, cur.Revision, p.ID, p.IdempotencyKey); err != nil {
			return restore(fmt.Errorf("CONFLICT: policy: %w", err))
		}
	}
	return nil
}


func netSplitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	if port == "" {
		return "", "", fmt.Errorf("empty port")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", fmt.Errorf("bad port %q", port)
		}
	}
	return host, port, nil
}


// validateOwnedStateName (B16): a user-supplied identifier used as a
// filename inside the owned state directory must be a safe relative name:
// no separators, no "..", no absolute paths (symlink escapes are handled
// by writing through atomic temp+rename inside the owned dir).
func validateOwnedStateName(name string) error {
	if name == "" {
		return nil // optional
	}
	if name == "." || name == ".." || strings.Contains(name, "..") ||
		strings.ContainsAny(name, "/\\\x00") || filepath.IsAbs(name) {
		return fmt.Errorf("identifier %q must be a plain filename inside the state directory", name)
	}
	return nil
}
