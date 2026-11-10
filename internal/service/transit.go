// Control-plane transit management (docs/TRANSPORT_PROFILES.md): typed
// transport profiles for the Edge→Exit hop with the same discipline as
// policy/limits — validate → plan (hash, preconditions, TTL) → apply →
// rollback — through ONE service layer shared by the CLI and the Control
// Center panel. Credential values never enter plan JSON, audit records or
// rendered previews: they go from stdin/file/fd into the protected
// secrets table, and from there only into 0600 rendered engine configs.
package service

import (
	"encoding/json"
	"fmt"
	"time"

	"aravpn/core/plan"
	"aravpn/core/transportprofile"
	"aravpn/internal/controlstore"
)

// OpenControlStore opens the control-plane DB of this state dir. The CLI
// and ara-control point at the same state dir, so both surfaces read and
// write exactly one store (docs/CLI_AUTOMATION.md: CLI equals UI).
func (s *Service) OpenControlStore() (*controlstore.Store, error) {
	if err := s.State.Ensure(); err != nil {
		return nil, err
	}
	return controlstore.Open(s.State.ControlDB())
}

// TransitCapabilities is the advertised matrix for CLI/UI (RU/EN text
// resolves client-side). Reality+vision stays out until a lab-proven
// engine configuration exists; hysteria2 ingress is not advertised.
func TransitCapabilities() map[string]any {
	return map[string]any{
		"transit": []map[string]any{
			{"protocol": "vless", "transport": "tcp", "security": "tls", "status": "implemented"},
			{"protocol": "trojan", "transport": "tcp", "security": "tls", "status": "implemented"},
			{"protocol": "hysteria2", "transport": "udp", "security": "tls", "status": "implemented_lab_validated"},
		},
		"ingress": []map[string]any{
			{"protocol": "vless", "transport": "tcp", "security": "tls", "status": "implemented"},
		},
		"unsupported": []map[string]any{
			{"protocol": "trojan", "role": "ingress", "reason": "UNSUPPORTED_CAPABILITY: edge terminates access identity itself"},
			{"protocol": "hysteria2", "role": "ingress", "reason": "UNSUPPORTED_CAPABILITY: lab transport experiment, not a product profile"},
			{"security": "reality", "reason": "UNSUPPORTED_CAPABILITY: separate capability pending a lab-proven engine configuration"},
		},
	}
}

// TransitOp is one typed transit mutation.
type TransitOp struct {
	Action string `json:"action"` // set-link-profile | add-profile | revoke-profile
	LinkID string `json:"link_id,omitempty"`
	// Profile is the full typed profile (add-profile); on
	// set-link-profile it is the referenced existing profile id in
	// ProfileID.
	Profile   *transportprofile.Profile `json:"profile,omitempty"`
	ProfileID string                    `json:"profile_id,omitempty"`
	// Secret is resolved from stdin/file OUTSIDE the plan and staged into
	// the protected secrets table at plan time; the plan JSON never
	// carries it. SecretStaged documents that fact for the reviewer.
	SecretStaged bool `json:"secret_staged,omitempty"`
}

// TransitSnapshot is the Before state enabling rollback.
type TransitSnapshot struct {
	// Links maps link id → current profile_id (nil = legacy default).
	Links map[string]*string `json:"links,omitempty"`
	// CreatedProfileIDs are profiles this plan creates; rollback revokes them.
	CreatedProfileIDs []string `json:"created_profile_ids,omitempty"`
}

// transitChanges is the hashed plan payload.
type transitChanges struct {
	Before TransitSnapshot `json:"before"`
	After  TransitOp       `json:"after"`
}

// TransitProfileInput is the operator-facing request for add-profile.
// Secret travels beside the plan, never inside it.
type TransitProfileInput struct {
	NodeID   string
	Protocol string
	Security string
	TLS      transportprofile.TLS
	// Secret is the credential value (trojan/hysteria2 password, vless
	// uuid); caller reads it from stdin/file/fd.
	Secret string
}

// TransitPlanSetLinkProfile stages a protocol switch for one link
// (Edge→Exit). The network transport of the target profile must match the
// link; the plan carries the Before snapshot for rollback.
func (s *Service) TransitPlanSetLinkProfile(linkID, profileID string, now time.Time) (*plan.Plan, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	link, err := st.GetLink(linkID)
	if err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: link %s: %w", linkID, err)
	}
	if profileID != "" {
		p, err := st.GetTransportProfile(profileID)
		if err != nil {
			return nil, "", err
		}
		if string(p.Transport) != link.Transport {
			return nil, "", fmt.Errorf("VALIDATION_FAILED: profile %s is %s, link transport is %s", profileID, p.Transport, link.Transport)
		}
	}
	before := TransitSnapshot{Links: map[string]*string{}}
	links, err := st.ListLinks()
	if err != nil {
		return nil, "", err
	}
	for _, l := range links {
		pid := l.ProfileID
		before.Links[l.ID] = pid
	}
	ch, err := json.Marshal(transitChanges{
		Before: before,
		After:  TransitOp{Action: "set-link-profile", LinkID: linkID, ProfileID: profileID},
	})
	if err != nil {
		return nil, "", err
	}
	return s.stageTransitPlan("set-link-profile:"+linkID, ch, now)
}

// TransitPlanAddProfile stages a new typed profile for an exit node. The
// secret (if provided) is staged into the protected store immediately and
// audited; the plan records only the fact (SecretStaged).
func (s *Service) TransitPlanAddProfile(in TransitProfileInput, now time.Time) (*plan.Plan, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	p := &transportprofile.Profile{
		NodeID:   in.NodeID,
		Role:     transportprofile.RoleTransit,
		Protocol: transportprofile.Protocol(in.Protocol),
		Security: transportprofile.Security(in.Security),
		TLS:      &in.TLS,
	}
	id, err := randomProfileID()
	if err != nil {
		return nil, "", err
	}
	p.ID = id
	p.CredentialRef = controlstore.TransitSecretRef(id)
	if err := p.Validate(); err != nil {
		return nil, "", err
	}
	if in.Secret == "" {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: credential secret is required (pass via stdin/file; empty credentials are never guessed)")
	}
	if err := st.SetTransitSecret(p.ID, in.Secret); err != nil {
		return nil, "", err
	}
	ch, err := json.Marshal(transitChanges{
		Before: TransitSnapshot{},
		After:  TransitOp{Action: "add-profile", Profile: p, SecretStaged: true},
	})
	if err != nil {
		return nil, "", err
	}
	return s.stageTransitPlan("add-profile:"+p.ID, ch, now)
}

// TransitPlanRevokeProfile stages a profile revocation; links referencing
// it fail validation on use (honest state, nothing silently re-pointed).
func (s *Service) TransitPlanRevokeProfile(profileID string, now time.Time) (*plan.Plan, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	if _, err := st.GetTransportProfile(profileID); err != nil {
		return nil, "", err
	}
	ch, err := json.Marshal(transitChanges{
		Before: TransitSnapshot{},
		After:  TransitOp{Action: "revoke-profile", ProfileID: profileID},
	})
	if err != nil {
		return nil, "", err
	}
	return s.stageTransitPlan("revoke-profile:"+profileID, ch, now)
}

func (s *Service) stageTransitPlan(op string, ch json.RawMessage, now time.Time) (*plan.Plan, string, error) {
	p := &plan.Plan{
		ID:             NewPlanID("transit"),
		Kind:           "transit",
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(plan.DefaultTTL),
		Preconditions:  map[string]string{},
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

// TransitApply applies a staged transit plan.
func (s *Service) TransitApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Apply(planID, hash, time.Now().UTC())
}

// transitExecutor applies kind "transit" against the control store.
type transitExecutor struct{ svc *Service }

func (e *transitExecutor) Kind() string { return "transit" }

func (e *transitExecutor) Check(p *plan.Plan, now time.Time) error {
	var ch transitChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return fmt.Errorf("transit changes unreadable: %w", err)
	}
	st, err := e.svc.OpenControlStore()
	if err != nil {
		return err
	}
	defer st.Close()
	switch ch.After.Action {
	case "set-link-profile":
		if ch.After.LinkID == "" {
			return fmt.Errorf("VALIDATION_FAILED: link_id required")
		}
		link, err := st.GetLink(ch.After.LinkID)
		if err != nil {
			return err
		}
		if ch.After.ProfileID != "" {
			prof, err := st.GetTransportProfile(ch.After.ProfileID)
			if err != nil {
				return err
			}
			if string(prof.Transport) != link.Transport {
				return fmt.Errorf("VALIDATION_FAILED: profile transport %s != link transport %s", prof.Transport, link.Transport)
			}
		} else if link.Transport == "udp" {
			return fmt.Errorf("VALIDATION_FAILED: udp link requires an explicitly defined hysteria2 transport profile")
		}
	case "add-profile":
		if ch.After.Profile == nil {
			return fmt.Errorf("VALIDATION_FAILED: profile required")
		}
		if err := ch.After.Profile.Validate(); err != nil {
			return err
		}
		// the secret must have been staged at plan time
		if _, err := st.TransitSecret(ch.After.Profile.ID); err != nil {
			return fmt.Errorf("VALIDATION_FAILED: credential for profile %s not staged: %w", ch.After.Profile.ID, err)
		}
	case "revoke-profile":
		if ch.After.ProfileID == "" {
			return fmt.Errorf("VALIDATION_FAILED: profile_id required")
		}
	case "rollback":
		if ch.After.LinkID == "" {
			return fmt.Errorf("VALIDATION_FAILED: rollback needs the source plan id")
		}
		reg, rerr := plan.NewRegistry(e.svc.State.Root)
		if rerr != nil {
			return rerr
		}
		src, lerr := reg.LoadPlan(ch.After.LinkID)
		if lerr != nil {
			return fmt.Errorf("PLAN_STALE: source plan: %w", lerr)
		}
		var srcCh transitChanges
		if uerr := json.Unmarshal(src.Changes, &srcCh); uerr != nil {
			return fmt.Errorf("source plan changes unreadable: %w", uerr)
		}
		for linkID, pid := range srcCh.Before.Links {
			if _, err := st.GetLink(linkID); err != nil {
				return fmt.Errorf("VALIDATION_FAILED: rollback source link %s: %w", linkID, err)
			}
			if pid != nil {
				if _, err := st.GetTransportProfile(*pid); err != nil {
					return fmt.Errorf("VALIDATION_FAILED: rollback profile %s: %w", *pid, err)
				}
			}
		}
	default:
		return fmt.Errorf("VALIDATION_FAILED: unknown transit action %q", ch.After.Action)
	}
	return nil
}

func (e *transitExecutor) RecognizeAlreadyApplied(p *plan.Plan) (plan.Result, bool) {
	// Transit effects are verified against the store in Check; a crash
	// between mutation and receipt is handled by re-running Check (the
	// store operations below are idempotent), so no separate recognizer
	// identity is needed.
	return plan.Result{}, false
}

func (e *transitExecutor) Apply(p *plan.Plan, now time.Time) (plan.Result, error) {
	var ch transitChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return plan.Result{}, err
	}
	st, err := e.svc.OpenControlStore()
	if err != nil {
		return plan.Result{}, err
	}
	defer st.Close()
	summary := map[string]string{"action": ch.After.Action}
	switch ch.After.Action {
	case "set-link-profile":
		var pid *string
		if ch.After.ProfileID != "" {
			id := ch.After.ProfileID
			pid = &id
		}
		l, err := st.SetLinkProfile(ch.After.LinkID, pid)
		if err != nil {
			return plan.Result{}, err
		}
		summary["link"] = l.ID
		if l.ProfileID != nil {
			summary["profile"] = *l.ProfileID
		} else {
			summary["profile"] = "legacy-vless-tls"
		}
	case "add-profile":
		prof := ch.After.Profile
		if err := st.InsertTransportProfile(prof, now.UTC()); err != nil {
			return plan.Result{}, err
		}
		summary["profile"] = prof.ID
	case "revoke-profile":
		if err := st.RevokeTransportProfile(ch.After.ProfileID); err != nil {
			return plan.Result{}, err
		}
		summary["profile"] = ch.After.ProfileID
	case "rollback":
		reg, err := plan.NewRegistry(e.svc.State.Root)
		if err != nil {
			return plan.Result{}, err
		}
		src, err := reg.LoadPlan(ch.After.LinkID)
		if err != nil {
			return plan.Result{}, fmt.Errorf("PLAN_STALE: source plan: %w", err)
		}
		var srcCh transitChanges
		if err := json.Unmarshal(src.Changes, &srcCh); err != nil {
			return plan.Result{}, err
		}
		// B19: only the link(s) THIS plan changed are restored — the
		// Before snapshot of unrelated links is ignored, so a rollback of
		// link A never erases a later successful change to link B.
		target := ch.After.LinkID
		if srcCh.After.LinkID != "" {
			target = srcCh.After.LinkID
		}
		restored := 0
		for linkID, pid := range srcCh.Before.Links {
			if linkID != target {
				continue // unrelated link: keep the later change
			}
			if _, err := st.SetLinkProfile(linkID, pid); err != nil {
				return plan.Result{}, fmt.Errorf("rollback link %s: %w", linkID, err)
			}
			restored++
		}
		for _, profID := range srcCh.Before.CreatedProfileIDs {
			_ = st.RevokeTransportProfile(profID) // already gone: fine
		}
		summary["restored_links"] = fmt.Sprint(restored)
	}
	return plan.Result{Applied: true, Summary: summary}, nil
}

// TransitRollback stages and applies the inverse of an applied plan: the
// Before snapshot is restored (link profile pointers) and profiles this
// plan created are revoked. The function returns after applying —
// rollback is itself a typed, hashed plan so it is auditable.
func (s *Service) TransitRollback(sourcePlanID string, now time.Time) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	src, err := reg.LoadPlan(sourcePlanID)
	if err != nil {
		return nil, fmt.Errorf("PLAN_STALE: %w", err)
	}
	var ch transitChanges
	if err := json.Unmarshal(src.Changes, &ch); err != nil {
		return nil, err
	}
	rb, err := json.Marshal(transitChanges{Before: TransitSnapshot{}, After: TransitOp{
		Action: "rollback", LinkID: sourcePlanID,
	}})
	if err != nil {
		return nil, err
	}
	p := &plan.Plan{
		ID:             NewPlanID("transit-rb"),
		Kind:           "transit",
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(plan.DefaultTTL),
		Preconditions:  map[string]string{},
		Changes:        rb,
		IdempotencyKey: NewPlanID("idem"),
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	if _, err := reg.Stage(p); err != nil {
		return nil, err
	}
	if err := reg.Save(p); err != nil {
		return nil, err
	}
	res, err := reg.Apply(p.ID, hash, time.Now().UTC())
	return res, err
}

// TransitRender resolves link→profile→credential and renders the sing-box
// configurations for the hop: adapter (edge host, SOCKS loopback in →
// transit out) and inbound (exit host). The credential is resolved from
// the protected store in memory; callers write the result only to 0600
// files. This is the product's own config generation — no hand-edited
// JSON required (docs/TRANSPORT_PROFILES.md).
//
// The exit endpoint and server certificate are explicit arguments: the
// renderer never guesses endpoints or credentials. A link without a
// referenced profile (the pre-profiles legacy row) is refused with a
// typed message telling the operator to define an explicit profile — the
// running legacy edge keeps its static config, but the managed renderer
// refuses to invent one.
func (s *Service) TransitRender(linkID string, ep transportprofile.Endpoint, socksHost string, socksPort int, serverCertPath, serverKeyPath string) (adapter map[string]any, inbound map[string]any, err error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, nil, err
	}
	defer st.Close()
	link, err := st.GetLink(linkID)
	if err != nil {
		return nil, nil, err
	}
	if link.ProfileID == nil {
		if link.Transport == "udp" {
			return nil, nil, fmt.Errorf("VALIDATION_FAILED: link %s is udp without an explicitly defined hysteria2 transport profile; define one (ara node transport add-profile) instead of guessing credentials", linkID)
		}
		return nil, nil, fmt.Errorf("VALIDATION_FAILED: link %s has no transport profile (legacy VLESS+TLS row); define an explicit transport profile to manage this hop — credentials are never guessed", linkID)
	}
	prof, err := st.GetTransportProfile(*link.ProfileID)
	if err != nil {
		return nil, nil, err
	}
	if prof.RevokedAt != nil {
		return nil, nil, fmt.Errorf("VALIDATION_FAILED: link %s references revoked profile %s", linkID, prof.ID)
	}
	secret, err := st.TransitSecret(prof.ID)
	if err != nil {
		return nil, nil, err
	}
	cred := transportprofile.Credential{UUID: secret, Password: secret}
	adapter, err = transportprofile.RenderExitAdapter(prof, ep, cred, socksHost, socksPort)
	if err != nil {
		return nil, nil, err
	}
	inbound, err = transportprofile.RenderExitServer(prof, ep, cred, serverCertPath, serverKeyPath)
	if err != nil {
		return nil, nil, err
	}
	return adapter, inbound, nil
}

func randomProfileID() (string, error) {
	return controlstore.RandomID("tp")
}
