// Declarative topology management (docs/CLI_AUTOMATION.md headless
// scenario): an operator agent with console access describes the desired
// nodes, transport profiles and links in ONE document; apply is
// idempotent, staged through the plan discipline, safe to resume after an
// interruption and never invents credentials — secret values come from
// files/env at apply time and land in the protected secrets store. Deletion
// is deliberately NOT part of the document: revocations are explicit typed
// operations so a stale doc can never silently disconnect users.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"aravpn/core/plan"
	"aravpn/core/transportprofile"
	"aravpn/internal/controlstore"
)

// TopologyDoc is the declarative control-plane document.
type TopologyDoc struct {
	Nodes []TopologyNodeDoc `json:"nodes,omitempty"`
	// TransportProfiles are exit transit profiles; Ref is the doc-local
	// identifier links reference.
	TransportProfiles []TransportProfileDoc `json:"transport_profiles,omitempty"`
	Links             []TopologyLinkDoc     `json:"links,omitempty"`
}

// TopologyNodeDoc declares one node (idempotent create).
type TopologyNodeDoc struct {
	ID       string `json:"id"`
	Country  string `json:"country"`
	Role     string `json:"role"` // ru | foreign
	Priority int    `json:"priority,omitempty"`
}

// TransportProfileDoc declares one typed transit profile. Exactly one of
// PasswordFile/PasswordEnv carries the credential reference; the VALUE
// never appears in the document (docs/SECURITY.md).
type TransportProfileDoc struct {
	Ref      string `json:"ref"`
	NodeID   string `json:"node_id"`
	Protocol string `json:"protocol"`
	Security string `json:"security,omitempty"`
	TLS      transportprofile.TLS `json:"tls"`
	// Credential source; resolved at apply time.
	PasswordFile string `json:"password_file,omitempty"`
	PasswordEnv  string `json:"password_env,omitempty"`
}

// TopologyLinkDoc declares an Edge→Exit association; ProfileRef names a
// TransportProfiles entry ("" = legacy tcp VLESS+TLS default).
type TopologyLinkDoc struct {
	EdgeID    string `json:"edge_id"`
	ExitID    string `json:"exit_id"`
	Transport string `json:"transport,omitempty"` // tcp (default) | udp
	Priority  int    `json:"priority,omitempty"`
	ProfileRef string `json:"profile_ref,omitempty"`
}

// Validate checks the document shape and typed profile rules without
// touching state.
func (d *TopologyDoc) Validate() error {
	if len(d.Nodes) == 0 && len(d.TransportProfiles) == 0 && len(d.Links) == 0 {
		return fmt.Errorf("VALIDATION_FAILED: topology document declares nothing")
	}
	refs := map[string]bool{}
	for i := range d.TransportProfiles {
		p := &d.TransportProfiles[i]
		if p.Ref == "" {
			return fmt.Errorf("VALIDATION_FAILED: transport_profiles[%d]: ref is required", i)
		}
		if refs[p.Ref] {
			return fmt.Errorf("VALIDATION_FAILED: transport profile ref %q duplicated", p.Ref)
		}
		refs[p.Ref] = true
		if p.Security == "" {
			p.Security = string(transportprofile.SecurityTLS)
		}
		if err := p.checkCredentialSource(); err != nil {
			return err
		}
		if err := p.typedProfile().Validate(); err != nil {
			return err
		}
	}
	nodeIDs := map[string]bool{}
	for _, n := range d.Nodes {
		if n.ID == "" || (n.Role != "ru" && n.Role != "foreign") {
			return fmt.Errorf("VALIDATION_FAILED: node %q: id and role ru|foreign are required", n.ID)
		}
		nodeIDs[n.ID] = true
	}
	for i, l := range d.Links {
		if l.EdgeID == "" || l.ExitID == "" {
			return fmt.Errorf("VALIDATION_FAILED: links[%d]: edge_id and exit_id are required", i)
		}
		if l.ProfileRef != "" && !refs[l.ProfileRef] {
			return fmt.Errorf("VALIDATION_FAILED: links[%d]: unknown profile_ref %q", i, l.ProfileRef)
		}
		if l.Transport == "" {
			d.Links[i].Transport = "tcp"
		}
	}
	return nil
}

func (p *TransportProfileDoc) checkCredentialSource() error {
	n := 0
	for _, s := range []string{p.PasswordFile, p.PasswordEnv} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("VALIDATION_FAILED: transport profile %q: exactly one of password_file|password_env is required (credentials are never inline)", p.Ref)
	}
	return nil
}

// secret resolves the credential from the declared source.
func (p *TransportProfileDoc) secret() (string, error) {
	if p.PasswordEnv != "" {
		v := os.Getenv(p.PasswordEnv)
		if v == "" {
			return "", fmt.Errorf("VALIDATION_FAILED: transport profile %q: env %s is empty", p.Ref, p.PasswordEnv)
		}
		return v, nil
	}
	b, err := os.ReadFile(p.PasswordFile)
	if err != nil {
		return "", fmt.Errorf("VALIDATION_FAILED: transport profile %q: password_file: %w", p.Ref, err)
	}
	// trim ONE trailing newline (editor artifact), never interior content
	s := string(b)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "", fmt.Errorf("VALIDATION_FAILED: transport profile %q: password_file is empty", p.Ref)
	}
	return s, nil
}

// typedProfile builds the core typed model (validation reuses it).
func (p *TransportProfileDoc) typedProfile() *transportprofile.Profile {
	id := DocProfileID(p.Ref)
	return &transportprofile.Profile{
		ID:       id,
		NodeID:   p.NodeID,
		Role:     transportprofile.RoleTransit,
		Protocol: transportprofile.Protocol(p.Protocol),
		Transport: func() transportprofile.Transport {
			if transportprofile.Protocol(p.Protocol) == transportprofile.ProtocolHysteria2 {
				return transportprofile.TransportUDP
			}
			return transportprofile.TransportTCP
		}(),
		Security:      transportprofile.Security(p.Security),
		TLS:           &p.TLS,
		CredentialRef: controlstore.TransitSecretRef(id),
	}
}

// DocProfileID derives the STABLE profile id from the document ref:
// re-running the same document maps to the same rows (idempotency and
// resume after interruption).
func DocProfileID(ref string) string {
	sum := sha256.Sum256([]byte("ara-topo:" + ref))
	return "tp-" + hex.EncodeToString(sum[:8])
}

// TopologyPlan validates the document and stages the plan. Secrets are
// NOT read at plan time (plan preview must be possible without access to
// credential files); the executor reads them at apply time.
func (s *Service) TopologyPlan(doc *TopologyDoc, now time.Time) (*plan.Plan, string, error) {
	if err := doc.Validate(); err != nil {
		return nil, "", err
	}
	ch, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	p := &plan.Plan{
		ID:             NewPlanID("topology"),
		Kind:           "topology",
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

// TopologyApply applies a staged topology plan.
func (s *Service) TopologyApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Apply(planID, hash, time.Now().UTC())
}

type topologyExecutor struct{ svc *Service }

func (e *topologyExecutor) Kind() string { return "topology" }

func (e *topologyExecutor) Check(p *plan.Plan, now time.Time) error {
	var doc TopologyDoc
	if err := json.Unmarshal(p.Changes, &doc); err != nil {
		return fmt.Errorf("topology changes unreadable: %w", err)
	}
	return doc.Validate()
}

func (e *topologyExecutor) RecognizeAlreadyApplied(p *plan.Plan) (plan.Result, bool) {
	// idempotent by construction (create-missing semantics): Check+Apply
	// re-run reaches the same state; no separate identity needed
	return plan.Result{}, false
}

func (e *topologyExecutor) Apply(p *plan.Plan, now time.Time) (plan.Result, error) {
	var doc TopologyDoc
	if err := json.Unmarshal(p.Changes, &doc); err != nil {
		return plan.Result{}, err
	}
	st, err := e.svc.OpenControlStore()
	if err != nil {
		return plan.Result{}, err
	}
	defer st.Close()
	summary := map[string]int{}
	// nodes: create missing only
	for _, n := range doc.Nodes {
		exists, err := st.NodeExists(n.ID)
		if err != nil {
			return plan.Result{}, err
		}
		if exists {
			summary["nodes_skipped"]++
			continue
		}
		if _, err := st.AddNode(n.ID, n.Country, n.Role, n.Priority); err != nil {
			return plan.Result{}, err
		}
		summary["nodes_created"]++
	}
	// profiles: create missing only (stable ids from refs); stage secrets
	byRef := map[string]*TransportProfileDoc{}
	for i := range doc.TransportProfiles {
		spec := &doc.TransportProfiles[i]
		byRef[spec.Ref] = spec
		id := DocProfileID(spec.Ref)
		if _, err := st.GetTransportProfile(id); err == nil {
			summary["profiles_skipped"]++
			continue
		}
		secret, err := spec.secret()
		if err != nil {
			return plan.Result{}, err
		}
		tp := spec.typedProfile()
		if _, err := st.AddTransportProfileWithID(tp, now.UTC()); err != nil {
			return plan.Result{}, err
		}
		if err := st.SetTransitSecret(tp.ID, secret); err != nil {
			return plan.Result{}, err
		}
		summary["profiles_created"]++
	}
	// links: create missing only
	for _, l := range doc.Links {
		transport := l.Transport
		if transport == "" {
			transport = "tcp"
		}
		var pid *string
		if l.ProfileRef != "" {
			id := DocProfileID(l.ProfileRef)
			pid = &id
		}
		existing, err := st.FindLink(l.EdgeID, l.ExitID)
		if err != nil {
			return plan.Result{}, err
		}
		if existing != nil {
			summary["links_skipped"]++
			continue
		}
		if _, err := st.AddLink(l.EdgeID, l.ExitID, transport, l.Priority, pid); err != nil {
			return plan.Result{}, err
		}
		summary["links_created"]++
	}
	byts, _ := json.Marshal(summary)
	return plan.Result{Applied: true, Summary: map[string]string{"changes": string(byts)}}, nil
}
