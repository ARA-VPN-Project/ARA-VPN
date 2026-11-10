package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/plan"
	"aravpn/core/policy"
	"aravpn/core/routing"
	"aravpn/internal/txlog"
)

func writeJSONAtomic(path string, v any) error { return plan.WriteJSONAtomic(path, v) }

// Policy txlog (review S04): the FULL effect (expected revision + whole
// policy document + operation identity) is durably appended BEFORE the
// mutation, and the outcome is appended after. A retry whose effect
// already committed but whose receipt/meta write failed recognizes its
// own operation from the intent record — the single durable transaction
// record carries identity, revision and content together.
type policyTx struct {
	Kind             string        `json:"kind"` // apply | applied
	PlanID           string        `json:"plan_id"`
	IdempotencyKey   string        `json:"idempotency_key"`
	ExpectedRevision int64         `json:"expected_revision"`
	Policy           policy.Policy `json:"policy"`
	NewRevision      int64         `json:"new_revision,omitempty"`
}

const txKindApply = "apply"

func (p *policyExecutor) txlog() *txlog.Log {
	l, _ := txlog.Open(filepath.Join(p.svc.State.PolicyDir(), "policy.txlog.jsonl"))
	return l
}

// PolicyValidate validates a candidate policy document end to end,
// normalizing user-typed domains first. Nothing is written.
func (s *Service) PolicyValidate(candidate *policy.Policy) error {
	if err := candidate.NormalizeDomains(); err != nil {
		return fmt.Errorf("VALIDATION_FAILED: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("POLICY_INVALID: %w", err)
	}
	return nil
}

type policyChanges struct {
	ExpectedRevision int64         `json:"expected_revision"`
	Policy           policy.Policy `json:"policy"`
}

// policyExecutor applies the "policy" kind: full validation, CAS on the
// revision the plan was computed from, atomic file swap with LKG refresh.
type policyExecutor struct {
	svc *Service
}

func (p *policyExecutor) Kind() string { return "policy" }

func (p *policyExecutor) Check(pl *plan.Plan, now time.Time) error {
	var ch policyChanges
	if err := json.Unmarshal(pl.Changes, &ch); err != nil {
		return fmt.Errorf("plan changes unreadable: %w", err)
	}
	store, err := p.svc.LoadPolicyStore()
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if cur.Revision != ch.ExpectedRevision {
		return fmt.Errorf("policy revision moved (plan expects %d, current %d)", ch.ExpectedRevision, cur.Revision)
	}
	cand := ch.Policy
	if err := cand.Validate(); err != nil {
		return fmt.Errorf("POLICY_INVALID: %w", err)
	}
	return nil
}

// RecognizeAlreadyApplied implements plan.EffectRecognizer (review R06 +
// S04 + T05): the AUTHORITATIVE identity is the state file's apply
// identity, committed atomically WITH the policy document. A txlog intent
// alone never proves the commit: two plans can share expected revision
// and content, so only the operation whose identity was atomically
// committed with the state may claim the effect. A retry whose receipt or
// meta write failed therefore recovers, while an intent-only plan that
// never mutated anything (or lost to an identical competing plan) gets
// its honest CONFLICT.
func (p *policyExecutor) RecognizeAlreadyApplied(pl *plan.Plan) (plan.Result, bool) {
	var ch policyChanges
	if err := json.Unmarshal(pl.Changes, &ch); err != nil {
		return plan.Result{}, false
	}
	store, err := p.svc.LoadPolicyStore()
	if err != nil {
		return plan.Result{}, false
	}
	cur, identity, err := store.LoadState()
	if err != nil || identity == nil || cur == nil {
		return plan.Result{}, false
	}
	if identity.PlanID != pl.ID || identity.IdempotencyKey != pl.IdempotencyKey {
		return plan.Result{}, false
	}
	if cur.Revision != ch.ExpectedRevision+1 {
		return plan.Result{}, false
	}
	cand := ch.Policy
	if err := cand.Validate(); err != nil {
		return plan.Result{}, false
	}
	if !samePolicyContent(cur, &cand) {
		return plan.Result{}, false
	}
	// record the outcome if it was lost too; idempotent when present
	_ = p.txlog().Append(policyTx{Kind: "applied", PlanID: pl.ID, IdempotencyKey: pl.IdempotencyKey, ExpectedRevision: ch.ExpectedRevision, Policy: ch.Policy, NewRevision: cur.Revision})
	return plan.Result{Applied: true, NewRevision: cur.Revision}, true
}

// samePolicyContent compares documents ignoring the assigned revision.
func samePolicyContent(a, b *policy.Policy) bool {
	x, y := *a, *b
	x.Revision, y.Revision = 0, 0
	ab, err1 := json.Marshal(&x)
	bb, err2 := json.Marshal(&y)
	return err1 == nil && err2 == nil && bytes.Equal(ab, bb)
}

func (p *policyExecutor) Apply(pl *plan.Plan, now time.Time) (plan.Result, error) {
	var ch policyChanges
	if err := json.Unmarshal(pl.Changes, &ch); err != nil {
		return plan.Result{}, err
	}
	store, err := p.svc.LoadPolicyStore()
	if err != nil {
		return plan.Result{}, err
	}
	cand := ch.Policy
	if err := cand.Validate(); err != nil {
		return plan.Result{}, fmt.Errorf("POLICY_INVALID: %w", err)
	}
	// Durable intent with the FULL effect serialized (audit trail; the
	// authoritative identity commit happens in the same atomic rename as
	// the policy document — review T05). A failed intent append aborts
	// BEFORE the mutation.
	if err := p.txlog().Append(policyTx{Kind: txKindApply, PlanID: pl.ID, IdempotencyKey: pl.IdempotencyKey, ExpectedRevision: ch.ExpectedRevision, Policy: ch.Policy}); err != nil {
		return plan.Result{}, fmt.Errorf("policy txlog intent write failed: %w", err)
	}
	applied, err := store.ValidateAndApplyIdentity(&cand, ch.ExpectedRevision, pl.ID, pl.IdempotencyKey)
	if err != nil {
		return plan.Result{}, err
	}
	// outcome marker; a lost marker is repaired by recognition
	if aerr := p.txlog().Append(policyTx{Kind: "applied", PlanID: pl.ID, IdempotencyKey: pl.IdempotencyKey, ExpectedRevision: ch.ExpectedRevision, Policy: ch.Policy, NewRevision: applied.Revision}); aerr != nil {
		return plan.Result{Applied: true, NewRevision: applied.Revision},
			fmt.Errorf("applied but outcome marker not recorded: %w", aerr)
	}
	// receipt for fast-path idempotency (recognition path also writes it)
	if rerr := writeJSONAtomic(p.receiptPath(pl), plan.Result{Applied: true, NewRevision: applied.Revision}); rerr != nil {
		return plan.Result{Applied: true, NewRevision: applied.Revision},
			fmt.Errorf("applied but result not recorded: %w", rerr)
	}
	// apply-meta: a derived identity cache of the last apply (reviewers
	// and tooling read it in one hop). It is NOT the identity source —
	// the txlog intent is; a failure writing this cache still fails the
	// apply visibly and the retry recognizes the effect from the txlog.
	meta := applyMeta{PlanID: pl.ID, IdempotencyKey: pl.IdempotencyKey, Revision: applied.Revision}
	if merr := writeJSONAtomic(p.metaPath(), meta); merr != nil {
		return plan.Result{Applied: true, NewRevision: applied.Revision},
			fmt.Errorf("applied but plan-id meta not recorded: %w", merr)
	}
	return plan.Result{Applied: true, NewRevision: applied.Revision}, nil
}

// applyMeta is the derived identity cache (see Apply); the authoritative
// operation identity lives in the txlog intent record.
type applyMeta struct {
	PlanID         string `json:"plan_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Revision       int64  `json:"revision"`
}

func (p *policyExecutor) metaPath() string {
	return filepath.Join(p.svc.State.PolicyDir(), "policy.apply-meta.json")
}

// receiptPath is the per-idempotency-key receipt maintained by the plan
// registry (Root/applied/<key>.json); the executor writes it with the
// same atomic writer so fast-path replay finds it.
func (p *policyExecutor) receiptPath(pl *plan.Plan) string {
	return filepath.Join(p.svc.State.Root, "applied", pl.IdempotencyKey+".json")
}

// PolicyPlan stages a policy change. candidate may carry user-typed
// domains; they are normalized before validation and the normalized
// document is what gets stored in the plan (reviewers see exactly what
// will be applied).
func (s *Service) PolicyPlan(candidate *policy.Policy, now time.Time) (*plan.Plan, string, error) {
	return s.policyPlan(candidate, now, false)
}

// PolicyPlanDraft requires the revision from which an interactive editor started.
func (s *Service) PolicyPlanDraft(candidate *policy.Policy, now time.Time) (*plan.Plan, string, error) {
	return s.policyPlan(candidate, now, true)
}

func (s *Service) policyPlan(candidate *policy.Policy, now time.Time, checkRevision bool) (*plan.Plan, string, error) {
	if err := candidate.NormalizeDomains(); err != nil {
		return nil, "", fmt.Errorf("VALIDATION_FAILED: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return nil, "", fmt.Errorf("POLICY_INVALID: %w", err)
	}
	store, err := s.LoadPolicyStore()
	if err != nil {
		return nil, "", err
	}
	cur, err := store.Load()
	if err != nil {
		return nil, "", err
	}
	if checkRevision && cur.Revision != candidate.Revision {
		return nil, "", fmt.Errorf("PLAN_STALE: draft revision %d, current revision %d", candidate.Revision, cur.Revision)
	}
	ch, err := json.Marshal(policyChanges{ExpectedRevision: cur.Revision, Policy: *candidate})
	if err != nil {
		return nil, "", err
	}
	p := &plan.Plan{
		ID:             NewPlanID("policy"),
		Kind:           "policy",
		CreatedAt:      now.UTC(),
		ExpiresAt:      now.UTC().Add(plan.DefaultTTL), // set before hashing: Stage would otherwise mutate after the hash
		Preconditions:  map[string]string{"policy.revision": fmt.Sprint(cur.Revision)},
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

// PolicyApply applies a staged policy plan under the plan discipline.
func (s *Service) PolicyApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Apply(planID, hash, time.Now().UTC())
}

// PolicyGet returns the active policy document.
func (s *Service) PolicyGet() (*policy.Policy, error) {
	store, err := s.LoadPolicyStore()
	if err != nil {
		return nil, err
	}
	return store.Load()
}

// PolicyPreviewExplain runs the REAL routing oracle over a DRAFT policy
// (not the active one): validates the draft, then explains the decision
// for the test destination using the same primitives as the live path.
// The preview never applies anything.
func (s *Service) PolicyPreviewExplain(draft *policy.Policy, domain, ip, proto string, port int) (map[string]any, error) {
	topo, err := s.LoadTopology()
	if err != nil {
		return nil, err
	}
	hs, err := s.LoadHealthSnapshot()
	if err != nil {
		return nil, err
	}
	return s.PolicyPreviewWithTopology(draft, domain, ip, proto, port,
		routing.Topology{Exits: topo.Exits, CurrentForeignID: topo.CurrentForeignID, AccessDown: topo.AccessDown}, hs)
}

// PolicyPreviewWithTopology evaluates a draft against observations from a specific Edge.
func (s *Service) PolicyPreviewWithTopology(draft *policy.Policy, domain, ip, proto string, port int, topo routing.Topology, hs routing.Snapshot) (map[string]any, error) {
	if err := s.PolicyValidate(draft); err != nil {
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
		topo,
		hs, draft, s.LoadSystemACL(), d, routing.QuotaState{Exhausted: quotaState}, 0,
	)
	return dec.ExplainView(), nil
}
