package main

// Route rule editor API:
// the Control Center edits the policy DRAFT in the browser, validates it
// through the SAME service-layer primitives the CLI/data plane use
// (PolicyValidate → PolicyPlan with revision CAS → PolicyApply), previews
// a test destination through the real routing oracle (RouteExplain), and
// never applies the draft implicitly. Parallel editors are protected by
// the plan preconditions (revision) — a stale draft fails with a typed
// conflict, the operator reloads the current state.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aravpn/core/health"
	"aravpn/core/policy"
	"aravpn/core/routing"
	"aravpn/internal/controlstore"
)

func policyAudit(action string, p *policy.Policy, planID string) controlstore.AuditEntry {
	return controlstore.AuditEntry{Actor: "panel", Action: action, ObjectID: planID, Result: "ok",
		Detail: fmt.Sprintf("rules=%d", len(p.Rules))}
}

// handlePolicyDraftValidate: POST the whole candidate policy → validate.
func (s *server) handlePolicyDraftValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	cand, err := decodePolicyBody(w, r)
	if err != nil {
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := svc.PolicyValidate(cand); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "rules": len(cand.Rules)})
}

// handlePolicyPreview: POST a destination + the candidate policy → the
// REAL routing decision over the draft (matched rule, action, reason,
// DNS scope). Nothing is applied; the draft is not required to be the
// active policy.
func (s *server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Candidate map[string]any `json:"candidate"`
		Domain    string         `json:"domain"`
		IP        string         `json:"ip"`
		Proto     string         `json:"proto"`
		Port      int            `json:"port"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(req.Candidate)
	var cand policy.Policy
	if err := json.Unmarshal(b, &cand); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED: candidate"}`, http.StatusBadRequest)
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	// preview = explain over the DRAFT: apply the same normalize/validate,
	// then run the real oracle through RouteExplain semantics against a
	// TEMPORARY store — implemented by validating + explaining on the
	// live store with the draft's rules injected via a fresh policy store.
	if err := svc.PolicyValidate(&cand); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var view map[string]any
	if s.edgeStatusPath == "" {
		view, err = svc.PolicyPreviewExplain(&cand, req.Domain, req.IP, req.Proto, req.Port)
	} else {
		now := time.Now()
		observation, _ := readEdgeObservation(s.edgeStatusPath, now)
		topo, snapshot := observation.routingInputs(now)
		view, err = svc.PolicyPreviewWithTopology(&cand, req.Domain, req.IP, req.Proto, req.Port, topo, snapshot)
		if err == nil {
			view["source"] = "local_edge_observation"
			view["observed_at"] = observation.At
		}
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (o edgeObservation) routingInputs(now time.Time) (routing.Topology, routing.Snapshot) {
	topo := routing.Topology{CurrentForeignID: o.CurrentForeign}
	snapshot := routing.Snapshot{}
	for _, n := range o.Nodes {
		role := routing.Role(n.Role)
		if n.ID == "" || (role != routing.RoleRU && role != routing.RoleForeign) {
			continue
		}
		topo.Exits = append(topo.Exits, routing.Exit{ID: n.ID, Country: n.Country, Role: role, Priority: n.Priority})
		if age := now.Sub(n.ProbeAt); age >= 0 && age <= 30*time.Second {
			snapshot[n.ID] = health.State(n.State)
		}
	}
	return topo, snapshot
}

func (s *server) handlePolicyPool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now()
	observed, err := readEdgeObservation(s.edgeStatusPath, now)
	if err != nil {
		writeJSON(w, 200, map[string]bool{"available": false})
		return
	}
	topo, snapshot := observed.routingInputs(now)
	d := routing.Decide(topo, snapshot, &policy.Policy{DefaultAction: policy.ActionForeignPool}, policy.SystemACL{}, policy.Destination{Domain: "example.net", Proto: policy.ProtoTCP, Port: 443}, routing.QuotaState{}, 0)
	writeJSON(w, 200, map[string]any{"available": true, "exit_id": d.ExitID, "country": d.Country})
}

// handlePolicyDiffPlan: POST candidate → plan with revision precondition
// (the browser sent the revision it saw). Response carries plan_id/hash —
// the apply posts them back; a parallel editor's apply fails PLAN_STALE.
func (s *server) handlePolicyDiffPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	cand, err := decodePolicyBody(w, r)
	if err != nil {
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	plan, hash, err := svc.PolicyPlanDraft(cand, time.Now().UTC())
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(policyAudit("policy.plan", cand, plan.ID))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"plan_id": plan.ID, "plan_hash": hash, "expires_at": plan.ExpiresAt,
		"expected_revision": plan.Preconditions["policy.revision"],
	})
}

// handlePolicyApplyApply: POST plan_id+plan_hash → apply; typed
// PLAN_STALE/PLAN_EXPIRED surface to the editor as a reload prompt.
func (s *server) handlePolicyApplyApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PlanID string `json:"plan_id"`
		Hash   string `json:"plan_hash"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || req.PlanID == "" {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := svc.PolicyApply(req.PlanID, req.Hash)
	if err != nil {
		writeErr(w, err) // PLAN_STALE etc — typed for the UI
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "panel", Action: "policy.apply", ObjectID: req.PlanID, Result: "ok"})
	writeJSON(w, http.StatusOK, res)
}

func decodePolicyBody(w http.ResponseWriter, r *http.Request) (*policy.Policy, error) {
	var cand map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&cand); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return nil, err
	}
	b, _ := json.Marshal(cand)
	var p policy.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED: candidate"}`, http.StatusBadRequest)
		return nil, err
	}
	return &p, nil
}
