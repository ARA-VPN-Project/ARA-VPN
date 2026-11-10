// Edge config auto-apply (docs/FEDERATION.md "автоматическое применение"):
// the agent drives the FULL flow from consoles —
//
//	ara node edge-config plan --edge-node edge-ru --subscription sub-... \
//	     --panel-id edge-ru-1 --owner-url http://... --access-listen ... → plan
//	ara node edge-config apply --plan ... --expected-hash ... → writes the
//	     0600 config under <state>/edge-configs/ AND registers it for the
//	     signed federation dispatch;
//	ara edge sync --base <owner> (on the EDGE host, its own state dir)
//	     pulls the config, validates the hash and writes it locally with a
//	     backup of the previous one (rollback = restore the .bak).
//
// No hidden hand-written JSON: devices come from the subscription's
// account, exits from the declared topology links, quota_remote and rate
// shares from the owner's authoritative state.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"aravpn/core/plan"
	"aravpn/internal/backbone"
	"aravpn/internal/controlstore"
)

var _ = controlstore.HashToken

// localPanelID returns this panel's identity id (owner of its own subs).
func localPanelID(s *Service) string {
	if pi := s.PanelIdentity(); pi != nil {
		return pi.PanelID
	}
	return ""
}

// validateOwnerBase applies the federation transport contract (B44) to a
// per-context owner endpoint.
func validateOwnerBase(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("VALIDATION_FAILED: owner base URL invalid: %q", base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "127.0.0.1" || h == "localhost" || h == "::1" {
			return nil
		}
		return fmt.Errorf("VALIDATION_FAILED: owner base must be HTTPS (loopback http allowed only): %q", base)
	default:
		return fmt.Errorf("VALIDATION_FAILED: owner base scheme %q not allowed", u.Scheme)
	}
}

// EdgeConfigInput is the operator-facing request.
type EdgeBackboneInput struct {
	Binding   backbone.Binding `json:"binding"`
	ProbeAddr string           `json:"probe_addr"`
}

type EdgeConfigInput struct {
	ExitBackbones map[string]EdgeBackboneInput `json:"exit_backbones,omitempty"`
	EdgeNodeID    string                       `json:"edge_node_id"`
	EdgePanelID   string                       `json:"edge_panel_id"` // the edge's federation identity
	Subscription  string                       `json:"subscription_id"`
	OwnerURL      string                       `json:"owner_url"`
	AccessListen  string                       `json:"access_listen"`
	SOCKSListen   string                       `json:"socks_listen,omitempty"`
	TLSCert       string                       `json:"tls_cert"`
	TLSKey        string                       `json:"tls_key"`
	CACert        string                       `json:"ca_cert"`
	StateDir      string                       `json:"state_dir"`
	StatusFile    string                       `json:"status_file"`
	LeaseBytes    int64                        `json:"lease_bytes,omitempty"`
	// ExitDNSAddr (B21): the exit-scoped resolver published into every
	// generated exit entry — required so domain destinations resolve
	// inside the exit's network scope, not on the Edge host.
	ExitDNSAddr string `json:"exit_dns_addr"`
	// PolicyFile (B21): the accepted policy document the Edge enforces.
	PolicyFile string `json:"policy_file,omitempty"`
	// OwnerURLs (C09): base URL per FOREIGN owner panel serving its
	// subscription on this edge. A delegated subscription whose owner base
	// is unknown refuses the whole plan — an unserved budget must never be
	// published as working.
	OwnerURLs map[string]string `json:"owner_urls,omitempty"`
}

// EdgeConfigStateDir returns where applied edge configs live.
func (s *StateDir) EdgeConfigsDir() string { return filepath.Join(s.Root, "edge-configs") }

// EdgeConfigPlan validates inputs against live state and stages a plan.
func (s *Service) EdgeConfigPlan(in EdgeConfigInput, now time.Time) (*plan.Plan, string, map[string]any, error) {
	if in.EdgeNodeID == "" || in.EdgePanelID == "" || in.Subscription == "" || in.OwnerURL == "" ||
		in.AccessListen == "" || in.TLSCert == "" || in.TLSKey == "" || in.CACert == "" {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: edge_node_id, edge_panel_id, subscription_id, owner_url, access_listen, tls_cert, tls_key and ca_cert are required")
	}
	// B16: EdgePanelID becomes a filename in the owned edge-configs dir.
	if err := validateOwnedStateName(in.EdgePanelID); err != nil {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: edge_panel_id: %w", err)
	}
	// B21: exit-scoped DNS is REQUIRED in the generated config — the data
	// plane resolves domain destinations through the exit's own resolver.
	if in.ExitDNSAddr == "" {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: exit_dns_addr is required (exit-scoped resolver)")
	}
	// B16: EdgePanelID becomes a filename in the owned edge-configs dir.
	if err := validateOwnedStateName(in.EdgePanelID); err != nil {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: edge_panel_id: %w", err)
	}
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", nil, err
	}
	defer st.Close()
	sub, err := st.GetSubscription(in.Subscription)
	if err != nil {
		return nil, "", nil, err
	}
	if sub.Active != nil && !*sub.Active {
		return nil, "", nil, fmt.Errorf("CONFLICT: subscription %s is imported-pending (ownership transfer in flight)", in.Subscription)
	}
	// B20: the Edge serves ALL subscriptions delegated to it. Every
	// subscription becomes an explicit serving CONTEXT (its own devices,
	// account and quota ledger); the flat device union stays for display
	// and legacy consumers. An identity maps to exactly one context.
	devices, err := st.ListDevices()
	if err != nil {
		return nil, "", nil, err
	}
	type edgeDevice struct {
		UUID        string `json:"uuid"`
		DeviceID    string `json:"device_id"`
		ExpiresUnix int64  `json:"expires_unix,omitempty"`
	}
	devIDs := map[string]bool{}
	var devs []edgeDevice
	subIDs := []string{sub.ID}
	addAccount := func(accountID string) {
		for _, d := range devices {
			if d.AccountID == accountID && d.RevokedAt == nil && d.VlessUUID != "" && !devIDs[d.ID] {
				devIDs[d.ID] = true
				devs = append(devs, edgeDevice{UUID: d.VlessUUID, DeviceID: d.ID, ExpiresUnix: d.ExpiresUnix})
			}
		}
	}
	addAccount(sub.AccountID)
	// other subscriptions delegated to this edge panel (per-object grants)
	subs, err := st.ListSubscriptions()
	if err != nil {
		return nil, "", nil, err
	}
	for _, other := range subs {
		if other.ID == sub.ID || other.RevokedAt != nil {
			continue
		}
		if st.EdgeSubscriptionDelegated(in.EdgePanelID, other.ID) {
			subIDs = append(subIDs, other.ID)
			addAccount(other.AccountID)
		}
	}
	if len(devs) == 0 {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: no active device identities across the delegated subscriptions")
	}
	// per-subscription serving contexts: subscription_id → account and its
	// device identities (the Edge runtime builds one ledger per context)
	type profileRate struct {
		DownloadBPS *int64 `json:"download_bps,omitempty"`
		UploadBPS   *int64 `json:"upload_bps,omitempty"`
	}
	type edgeSubContext struct {
		ProfileBudgets map[int]string      `json:"profile_budgets,omitempty"`
		ProfileRates   map[int]profileRate `json:"profile_rates,omitempty"`
		SubscriptionID string              `json:"subscription_id"`
		AccountID      string              `json:"account_id,omitempty"`
		// OwnerURL (C09): the AUTHORITATIVE budget endpoint of THIS
		// subscription's owner panel — ledgers of different owners never
		// share one OwnerURL.
		OwnerURL string `json:"owner_url,omitempty"`
		// Routes (C05): the exits THIS subscription is allowed to reach
		// through pinned route listeners; the runtime enforces the grant
		// server-side before any egress.
		Routes        []string     `json:"routes,omitempty"`
		PolicyRouting bool         `json:"policy_routing,omitempty"`
		Devices       []edgeDevice `json:"devices"`
	}
	var contexts []edgeSubContext
	ctxDevs := map[string]bool{}
	// transit routes referenced by each subscription's published profiles
	subRoutes := map[string][]string{}
	policyIngress := map[string]string{}
	profs, perr := st.ListSubscriptionProfilesAll()
	if perr == nil {
		for _, pr := range profs {
			if pr.Kind == "transit" && pr.RoutePort == 0 && pr.NodeID == in.EdgeNodeID {
				policyIngress[pr.SubscriptionID] = pr.IngressAddr
			}
		}
		for _, pr := range profs {
			ingress := policyIngress[pr.SubscriptionID]
			if pr.Kind == "transit" && pr.RoutePort > 0 && (ingress == "" || ingress == pr.IngressAddr) {
				subRoutes[pr.SubscriptionID] = append(subRoutes[pr.SubscriptionID], pr.NodeID)
			}
		}
	}
	for _, sid := range subIDs {
		sctx, gerr := st.GetSubscription(sid)
		if gerr != nil {
			return nil, "", nil, gerr
		}
		// C09: per-context owner endpoint
		owner := in.OwnerURL
		if sctx.OwnerPanel != "" && sctx.OwnerPanel != localPanelID(s) {
			owner = in.OwnerURLs[sctx.OwnerPanel]
			if owner == "" {
				return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: delegated subscription %s is owned by panel %s — provide owner_urls[%s] or the budget cannot be served", sid, sctx.OwnerPanel, sctx.OwnerPanel)
			}
			if verr := validateOwnerBase(owner); verr != nil {
				return nil, "", nil, verr
			}
		}
		var cdevs []edgeDevice
		for _, d := range devices {
			if d.AccountID != sctx.AccountID || d.RevokedAt != nil || d.VlessUUID == "" {
				continue
			}
			if !devIDs[d.ID] || ctxDevs[d.ID] {
				continue
			}
			ctxDevs[d.ID] = true
			cdevs = append(cdevs, edgeDevice{UUID: d.VlessUUID, DeviceID: d.ID, ExpiresUnix: d.ExpiresUnix})
		}
		if len(cdevs) == 0 {
			continue
		}
		rates := map[int]profileRate{}
		budgets := map[int]string{}
		for _, p := range profs {
			if p.SubscriptionID != sid {
				continue
			}
			port := p.RoutePort
			if port == 0 {
				if p.NodeID != in.EdgeNodeID {
					continue
				}
			} else {
				n, err := st.GetNode(in.EdgeNodeID)
				if err != nil || p.IngressAddr != n.IngressAddr {
					continue
				}
			}
			budgets[port] = controlstore.ProfileKey(p)
			if p.DownloadBPS != nil || p.UploadBPS != nil {
				rates[port] = profileRate{p.DownloadBPS, p.UploadBPS}
			}
		}
		contexts = append(contexts, edgeSubContext{SubscriptionID: sid, AccountID: sctx.AccountID,
			ProfileBudgets: budgets, ProfileRates: rates, OwnerURL: owner, Routes: subRoutes[sid], PolicyRouting: policyIngress[sid] != "", Devices: cdevs})
	}
	// exits: the declared topology links of this edge node
	links, err := st.ListLinks()
	if err != nil {
		return nil, "", nil, err
	}
	nodes, err := st.ListNodes()
	if err != nil {
		return nil, "", nil, err
	}
	nodeByID := map[string]controlstore.Node{}
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	if _, ok := nodeByID[in.EdgeNodeID]; !ok {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: edge node %s not found", in.EdgeNodeID)
	}
	type edgeExit struct {
		Backbone  *backbone.Binding `json:"backbone,omitempty"`
		ProbeAddr string            `json:"probe_addr,omitempty"`
		ID        string            `json:"id"`
		Country   string            `json:"country"`
		Role      string            `json:"role"`
		Priority  int               `json:"priority"`
		SOCKSAddr string            `json:"socks_addr"`
		DNSAddr   string            `json:"dns_addr,omitempty"`
	}
	var exits []edgeExit
	port := 1171
	backbonesUsed := 0
	for _, l := range links {
		if l.EdgeID != in.EdgeNodeID {
			continue
		}
		n, ok := nodeByID[l.ExitID]
		if !ok {
			continue
		}
		exit := edgeExit{ID: n.ID, Country: n.Country, Role: n.Role,
			Priority: l.Priority, SOCKSAddr: fmt.Sprintf("127.0.0.1:%d", port), DNSAddr: in.ExitDNSAddr}
		if custom, ok := in.ExitBackbones[n.ID]; ok {
			if err := custom.Binding.Validate(); err != nil {
				return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: exit %s: %w", n.ID, err)
			}
			if _, _, err := net.SplitHostPort(custom.ProbeAddr); err != nil {
				return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: exit %s requires a canary host:port", n.ID)
			}
			exit.Backbone, exit.SOCKSAddr, exit.ProbeAddr = &custom.Binding, "", custom.ProbeAddr
			backbonesUsed++
		}
		exits = append(exits, exit)
		port++
	}
	if backbonesUsed != len(in.ExitBackbones) {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: backbone configured for an exit outside this Edge")
	}
	if len(exits) == 0 {
		return nil, "", nil, fmt.Errorf("VALIDATION_FAILED: node %s has no links (declare the topology first)", in.EdgeNodeID)
	}
	for i := range exits {
		exits[i].DNSAddr = in.ExitDNSAddr
	}
	// B23: one dedicated pinned listener per published edge→exit route.
	// Port allocation is STABLE and collision-free: 40000 + index over the
	// lexicographically sorted exit ids — equal link priorities never
	// collide, a priority change never reshuffles existing ports, and the
	// range is checked (65535 cap).
	exitIDs := make([]string, 0, len(exits))
	for _, e := range exits {
		exitIDs = append(exitIDs, e.ID)
	}
	sort.Strings(exitIDs)
	// C04: the durable registry decides — a published endpoint never
	// remaps; the hash derivation is only the fallback base.
	portOf := map[string]int{}
	for _, id := range exitIDs {
		if rp, ok := st.RoutePortOf(in.EdgeNodeID, id); ok {
			portOf[id] = rp
			continue
		}
		rp, rerr := st.AllocateRoutePort(in.EdgeNodeID, id)
		if rerr != nil {
			return nil, "", nil, rerr
		}
		portOf[id] = rp
	}
	routeHost := ""
	if h, _, err := net.SplitHostPort(in.AccessListen); err == nil {
		routeHost = h
	}
	type edgeRoute struct {
		Listen string `json:"listen"`
		ExitID string `json:"exit_id"`
	}
	var routes []edgeRoute
	for _, id := range exitIDs {
		routes = append(routes, edgeRoute{Listen: fmt.Sprintf("%s:%d", routeHost, portOf[id]), ExitID: id})
	}
	// B21: the accepted policy document travels with the generated config
	// (the Edge enforces the panel's source of truth, not a local copy)
	polStore, err := s.LoadPolicyStore()
	if err != nil {
		return nil, "", nil, err
	}
	polDoc, err := polStore.Load()
	if err != nil {
		return nil, "", nil, err
	}
	cfg := map[string]any{
		"access_listen": in.AccessListen,
		"socks_listen":  in.SOCKSListen,
		"tls_cert":      in.TLSCert, "tls_key": in.TLSKey, "ca_cert": in.CACert,
		"devices":     devs,
		"state_dir":   in.StateDir,
		"status_file": in.StatusFile,
		"current_foreign_id": func() string {
			if len(exits) > 0 {
				return exits[0].ID
			}
			return ""
		}(),
		"quota_bytes":      1 << 30, // local safety cap; the shared budget is authoritative
		"probe_interval_s": 2, "probe_timeout_ms": 3000,
		"exits": exits,
		"quota_remote": map[string]any{
			"subscription_id": in.Subscription,
			"owner_url":       in.OwnerURL,
			"panel_id":        in.EdgePanelID,
		},
		"policy":        polDoc,
		"subscriptions": contexts,
		"routes":        routes,
	}
	if in.LeaseBytes > 0 {
		cfg["quota_remote"].(map[string]any)["lease_bytes"] = in.LeaseBytes
	}
	if in.PolicyFile != "" {
		cfg["policy_file"] = in.PolicyFile
	}
	ch, err := json.Marshal(map[string]any{"edge_panel_id": in.EdgePanelID, "config": cfg})
	if err != nil {
		return nil, "", nil, err
	}
	p := &plan.Plan{
		ID: NewPlanID("edgeconfig"), Kind: "edgeconfig",
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(plan.DefaultTTL),
		Preconditions:  map[string]string{},
		Changes:        ch,
		IdempotencyKey: NewPlanID("idem"),
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, "", nil, err
	}
	reg, err := s.planRegistry()
	if err != nil {
		return nil, "", nil, err
	}
	if _, err := reg.Stage(p); err != nil {
		return nil, "", nil, err
	}
	if err := reg.Save(p); err != nil {
		return nil, "", nil, err
	}
	return p, hash, cfg, nil
}

// EdgeConfigApply applies a staged plan: writes the 0600 config file with
// a backup of the previous one (rollback = restore .bak) and registers it
// for the signed federation dispatch to the edge.
func (s *Service) EdgeConfigApply(planID, hash string) (*plan.Result, error) {
	reg, err := s.planRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Apply(planID, hash, time.Now().UTC())
}

type edgeConfigExecutor struct{ svc *Service }

func (e *edgeConfigExecutor) Kind() string { return "edgeconfig" }

type edgeConfigChanges struct {
	EdgePanelID string         `json:"edge_panel_id"`
	Config      map[string]any `json:"config"`
}

func (e *edgeConfigExecutor) Check(p *plan.Plan, now time.Time) error {
	var ch edgeConfigChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return fmt.Errorf("edgeconfig changes unreadable: %w", err)
	}
	if ch.EdgePanelID == "" || ch.Config == nil {
		return fmt.Errorf("VALIDATION_FAILED: edge_panel_id and config are required")
	}
	// B21: re-check the pinned published policy revision at APPLY time —
	// a plan staged before a policy change must not publish stale rules.
	if polDoc, ok := ch.Config["policy"].(map[string]any); ok {
		if rev, ok := polDoc["revision"].(float64); ok {
			store, err := e.svc.LoadPolicyStore()
			if err != nil {
				return err
			}
			cur, err := store.Load()
			if err != nil {
				return err
			}
			if fmt.Sprint(cur.Revision) != fmt.Sprint(int64(rev)) {
				return fmt.Errorf("CONFLICT: policy revision moved (plan pinned %d, current %d)", int64(rev), cur.Revision)
			}
		}
	}
	// B22: re-check the subscription lifecycle at APPLY time — a plan
	// staged before a revocation must not publish stale credentials.
	if qr, ok := ch.Config["quota_remote"].(map[string]any); ok {
		if subID, _ := qr["subscription_id"].(string); subID != "" {
			st, err := e.svc.OpenControlStore()
			if err != nil {
				return err
			}
			defer st.Close()
			sub, err := st.GetSubscription(subID)
			if err != nil {
				return fmt.Errorf("CONFLICT: subscription %s unavailable: %w", subID, err)
			}
			if sub.RevokedAt != nil {
				return fmt.Errorf("CONFLICT: subscription %s was revoked after this plan was staged", subID)
			}
			if sub.Active != nil && !*sub.Active {
				return fmt.Errorf("CONFLICT: subscription %s is a pending transfer copy", subID)
			}
		}
	}
	return nil
}

func (e *edgeConfigExecutor) RecognizeAlreadyApplied(p *plan.Plan) (plan.Result, bool) {
	return plan.Result{}, false
}

func (e *edgeConfigExecutor) Apply(p *plan.Plan, now time.Time) (plan.Result, error) {
	var ch edgeConfigChanges
	if err := json.Unmarshal(p.Changes, &ch); err != nil {
		return plan.Result{}, err
	}
	// B22: Apply re-verifies revocation too (Check ran earlier; the state
	// may have changed between Check and Apply).
	if qr, ok := ch.Config["quota_remote"].(map[string]any); ok {
		if subID, _ := qr["subscription_id"].(string); subID != "" {
			st, err := e.svc.OpenControlStore()
			if err != nil {
				return plan.Result{}, err
			}
			sub, err := st.GetSubscription(subID)
			st.Close()
			if err != nil {
				return plan.Result{}, err
			}
			if sub.RevokedAt != nil || (sub.Active != nil && !*sub.Active) {
				return plan.Result{}, fmt.Errorf("CONFLICT: subscription %s revoked or pending transfer", subID)
			}
		}
	}
	dir := e.svc.State.EdgeConfigsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return plan.Result{}, err
	}
	path := filepath.Join(dir, ch.EdgePanelID+".json")
	b, err := json.MarshalIndent(ch.Config, "", "  ")
	if err != nil {
		return plan.Result{}, err
	}
	b = append(b, '\n')
	sum := sha256.Sum256(b)
	cfgHash := hex.EncodeToString(sum[:])
	// backup the previous version for rollback
	if prev, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", prev, 0o600)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return plan.Result{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return plan.Result{}, err
	}
	st, err := e.svc.OpenControlStore()
	if err != nil {
		return plan.Result{}, err
	}
	defer st.Close()
	if err := st.StoreEdgeConfig(ch.EdgePanelID, string(b), cfgHash); err != nil {
		return plan.Result{}, err
	}
	// B05: the applied config names its subscription — grant this edge the
	// per-object quota/dispatch delegation for exactly that subscription.
	if qr, ok := ch.Config["quota_remote"].(map[string]any); ok {
		if subID, _ := qr["subscription_id"].(string); subID != "" {
			_ = st.GrantEdgeSubscriptionDelegation(ch.EdgePanelID, subID, "edge-config-apply")
		}
	}
	return plan.Result{Applied: true, Summary: map[string]string{
		"path": path, "hash": cfgHash, "edge_panel_id": ch.EdgePanelID,
	}}, nil
}

// EdgeSyncPull is the EDGE side: fetch the signed dispatch from the owner
// and report whether the local file must be updated.
type EdgeSyncPull struct {
	Changed   bool   `json:"changed"`
	Hash      string `json:"hash"`
	Path      string `json:"path"`
	ConfigRaw string `json:"-"`
}
