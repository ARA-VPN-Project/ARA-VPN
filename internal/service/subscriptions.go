// Subscription and federation service (docs/FEDERATION.md): ONE
// authoritative owner panel per subscription; delegated management goes
// through signed federation calls; the multi-profile catalog serves real
// client configs (direct DE/NL and transit RU→DE/NL); the shared quota
// ledger is the single budget — transfer moves the spend with the user,
// never resets it.
package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"

	"aravpn/core/fedauth"
	"aravpn/internal/clientengine"
	"aravpn/internal/controlstore"
)

var countryRU = map[string]string{"DE": "Германия", "NL": "Нидерланды", "RU": "Россия"}

// accusative forms for «X через Y» labels
var countryRUAcc = map[string]string{"DE": "Германию", "NL": "Нидерланды", "RU": "Россию"}
var countryEN = map[string]string{"DE": "Germany", "NL": "Netherlands", "RU": "Russia"}

func profileLabels(kind, exitCountry, edgeCountry string) (ru, en string) {
	cRU, okRU := countryRU[exitCountry]
	cEN := exitCountry
	if !okRU {
		region, err := language.ParseRegion(exitCountry)
		if err == nil {
			cRU = display.Regions(language.Russian).Name(region)
			cEN = display.Regions(language.English).Name(region)
		} else {
			cRU = exitCountry
		}
	} else {
		cEN = countryEN[exitCountry]
	}
	if kind == "direct" {
		return cRU + " напрямую", cEN + " direct"
	}
	eRU := edgeCountry
	eEN := edgeCountry
	if v, ok := countryRUAcc[edgeCountry]; ok {
		eRU = v
	}
	if v, ok := countryEN[edgeCountry]; ok {
		eEN = v
	}
	return cRU + " через " + eRU, cEN + " via " + eEN
}

// SubscriptionInput is one requested catalog entry.
type SubscriptionInput struct {
	ClientName string `json:"name"`
	LimitBytes *int64 `json:"limit_bytes"`
	Kind       string `json:"kind"`    // direct | transit | policy
	NodeID     string `json:"node_id"` // exit node for transit; ingress node for direct
	// EdgeNodeID (B23): for transit profiles — the RU ingress that serves
	// this route. Two profiles "RU-1→DE" and "RU-2→DE" differ in EdgeNodeID
	// and produce DIFFERENT client endpoints on the wire.
	EdgeNodeID  string `json:"edge_node_id"`
	DownloadBPS *int64 `json:"download_bps"`
	UploadBPS   *int64 `json:"upload_bps"`
}

// SubscriptionCreate makes the subscription and its initial catalog.
// The local panel is the authoritative owner.
func (s *Service) SubscriptionCreate(accountID, name string, limitsBytes *int64, ttl time.Duration, inputs []SubscriptionInput) (*controlstore.Subscription, string, error) {
	return s.SubscriptionCreateWithDeviceLimit(accountID, name, limitsBytes, ttl, inputs, nil)
}

func (s *Service) SubscriptionCreateWithDeviceLimit(accountID, name string, limitsBytes *int64, ttl time.Duration, inputs []SubscriptionInput, maxDevices *int) (*controlstore.Subscription, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	profiles, err := s.resolveSubscriptionProfiles(st, inputs)
	if err != nil {
		return nil, "", err
	}
	return st.CreateSubscriptionWithProfiles(accountID, name, s.PanelID(), limitsBytes, ttl, maxDevices, profiles)
}

// ProvisionSubscription creates the account, primary device and catalog atomically.
// Used by the first-run UI; explicit CLI create retains its existing-account contract.
func (s *Service) ProvisionSubscription(account, name string, limit *int64, ttl time.Duration, inputs []SubscriptionInput, maxDevices *int) (*controlstore.Subscription, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	profiles, err := s.resolveSubscriptionProfiles(st, inputs)
	if err != nil {
		return nil, "", err
	}
	return st.ProvisionLocalSubscription(account, name, s.PanelID(), limit, ttl, maxDevices, profiles)
}

// subscriptionApplyProfiles resolves each input to a concrete ingress
// (direct node's own ingress_addr, or the RU edge's for transit) and
// writes the labeled catalog.
func (s *Service) subscriptionApplyProfiles(st *controlstore.Store, subID string, inputs []SubscriptionInput) error {
	profiles, err := s.resolveSubscriptionProfiles(st, inputs)
	if err != nil {
		return err
	}
	return st.SetOwnedSubscriptionProfiles(subID, s.PanelID(), profiles)
}

func (s *Service) ProvisionLocalSubscription(accountID, name string, limitsBytes *int64, ttl time.Duration, inputs []SubscriptionInput, maxDevices *int, edge string, ruPort int) (*controlstore.Subscription, string, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, "", err
	}
	defer st.Close()
	profiles, err := s.resolveLocalProfiles(st, inputs, edge, ruPort)
	if err != nil {
		return nil, "", err
	}
	return st.ProvisionLocalSubscription(accountID, name, s.PanelID(), limitsBytes, ttl, maxDevices, profiles)
}

func (s *Service) SetLocalSubscriptionProfiles(id string, inputs []SubscriptionInput, edge string, ruPort int) error {
	st, err := s.OpenControlStore()
	if err != nil {
		return err
	}
	defer st.Close()
	profiles, err := s.resolveLocalProfiles(st, inputs, edge, ruPort)
	if err != nil {
		return err
	}
	return st.SetOwnedSubscriptionProfiles(id, s.PanelID(), profiles)
}

func (s *Service) resolveLocalProfiles(st *controlstore.Store, inputs []SubscriptionInput, edge string, ruPort int) ([]controlstore.SubscriptionProfile, error) {
	for i := range inputs {
		p := &inputs[i]
		switch p.Kind {
		case "policy", "direct":
			if p.NodeID != edge || p.Kind == "direct" && ruPort == 0 {
				return nil, fmt.Errorf("VALIDATION_FAILED: selected ingress is not served by this panel")
			}
		case "transit":
			if p.EdgeNodeID != edge {
				return nil, fmt.Errorf("VALIDATION_FAILED: select a route from the local ingress")
			}
		}
	}
	profiles, err := s.resolveSubscriptionProfilesFor(st, inputs, true)
	if err != nil {
		return nil, err
	}
	for i := range profiles {
		p := &profiles[i]
		for _, rate := range []*int64{inputs[i].DownloadBPS, inputs[i].UploadBPS} {
			if rate != nil && (*rate < 0 || *rate > 1_000_000_000_000 || *rate > 0 && (*rate < 8192 || *rate%8 != 0)) {
				return nil, fmt.Errorf("VALIDATION_FAILED: profile rate must be 0 or at least 8192 bit/s in multiples of 8")
			}
		}
		p.DownloadBPS, p.UploadBPS = inputs[i].DownloadBPS, inputs[i].UploadBPS
		if p.Kind == "direct" {
			p.RoutePort = ruPort
			if n, err := st.GetNode(edge); err == nil {
				p.LabelRU, p.LabelEn = profileLabels("direct", n.Country, "")
			}
		}
		if p.Kind == "transit" && p.RoutePort == 0 {
			p.LabelRU, p.LabelEn = "По правилам · "+edge, "Server rules · "+edge
		}
	}
	for i, in := range inputs {
		if name := strings.TrimSpace(in.ClientName); name != "" {
			profiles[i].LabelRU = name
			profiles[i].LabelEn = name
		}
	}
	return profiles, nil
}

func (s *Service) resolveSubscriptionProfiles(st *controlstore.Store, inputs []SubscriptionInput) ([]controlstore.SubscriptionProfile, error) {
	return s.resolveSubscriptionProfilesFor(st, inputs, false)
}

func (s *Service) resolveSubscriptionProfilesFor(st *controlstore.Store, inputs []SubscriptionInput, local bool) ([]controlstore.SubscriptionProfile, error) {
	profs := make([]controlstore.SubscriptionProfile, 0, len(inputs))
	for _, in := range inputs {
		switch in.Kind {
		case "policy":
			edge, err := st.GetNode(in.NodeID)
			if err != nil {
				return nil, err
			}
			if edge.Role != "ru" || edge.RevokedAt != nil || edge.IngressAddr == "" {
				return nil, fmt.Errorf("VALIDATION_FAILED: policy profile needs an active RU ingress")
			}
			profs = append(profs, controlstore.SubscriptionProfile{
				LabelRU: "По правилам · " + edge.ID, LabelEn: "By routing rules · " + edge.ID,
				Kind: "transit", NodeID: edge.ID, IngressAddr: edge.IngressAddr, SNI: edge.IngressSNI, Protocol: "vless",
			})
		case "direct":
			n, err := st.GetNode(in.NodeID)
			if err != nil {
				return nil, err
			}
			if n.IngressAddr == "" {
				return nil, fmt.Errorf("VALIDATION_FAILED: node %s has no client ingress (direct profile needs an ingress node)", in.NodeID)
			}
			ru, en := profileLabels("direct", n.Country, "")
			profs = append(profs, controlstore.SubscriptionProfile{
				LabelRU: ru, LabelEn: en, Kind: "direct", NodeID: n.ID,
				IngressAddr: n.IngressAddr, SNI: n.IngressSNI, Protocol: "vless",
			})
		case "transit":
			// transit profile: edge = an RU-role node with ingress; when
			// EdgeNodeID is given explicitly (B23), THAT ingress serves the
			// route (RU-1→DE vs RU-2→DE are distinct routes); otherwise the
			// first linked RU edge is used.
			var edge *controlstore.Node
			var err error
			if in.EdgeNodeID != "" {
				edge, err = st.GetNode(in.EdgeNodeID)
				if err != nil {
					return nil, err
				}
				if edge.Role != "ru" || edge.RevokedAt != nil || edge.IngressAddr == "" {
					return nil, fmt.Errorf("VALIDATION_FAILED: node %s is not a live RU ingress (role/ingress)", in.EdgeNodeID)
				}
				links, lerr := st.ListLinks()
				if lerr != nil {
					return nil, lerr
				}
				linked := false
				for _, l := range links {
					if l.EdgeID == edge.ID && l.ExitID == in.NodeID {
						linked = true
						break
					}
				}
				if !linked {
					return nil, fmt.Errorf("VALIDATION_FAILED: no link %s→%s", in.EdgeNodeID, in.NodeID)
				}
			} else {
				edge, err = s.findTransitEdge(st, in.NodeID)
				if err != nil {
					return nil, err
				}
			}
			exitNode, err := st.GetNode(in.NodeID)
			if err != nil {
				return nil, err
			}
			ru, en := profileLabels("transit", exitNode.Country, edge.Country)
			// B23/C04: the route port comes from the DURABLE registry
			// (edge, exit) → port: a published endpoint never remaps when
			// the exit set changes; the hash derivation is only the
			// deterministic fallback.
			routePort := 0
			if rp, rerr := st.AllocateRoutePort(edge.ID, in.NodeID); rerr == nil {
				routePort = rp
			} else {
				links, lerr := st.ListLinks()
				if lerr == nil {
					var edgeExits []string
					for _, l := range links {
						if l.EdgeID == edge.ID {
							edgeExits = append(edgeExits, l.ExitID)
						}
					}
					if p, perr := RoutePortForExit(edgeExits, in.NodeID); perr == nil {
						routePort = p
					}
				}
			}
			profs = append(profs, controlstore.SubscriptionProfile{
				LabelRU: ru, LabelEn: en, Kind: "transit", NodeID: in.NodeID,
				IngressAddr: edge.IngressAddr, SNI: edge.IngressSNI, Protocol: "vless",
				RoutePort: routePort,
			})
		default:
			return nil, fmt.Errorf("VALIDATION_FAILED: kind must be direct|transit|policy (got %q)", in.Kind)
		}
	}
	if len(profs) == 0 {
		return nil, fmt.Errorf("VALIDATION_FAILED: at least one profile is required")
	}
	seenProfiles := map[string]bool{}
	for i, in := range inputs {
		key := controlstore.ProfileKey(profs[i])
		if seenProfiles[key] {
			return nil, fmt.Errorf("VALIDATION_FAILED: duplicate profile route")
		}
		seenProfiles[key] = true
		for _, rate := range []*int64{in.DownloadBPS, in.UploadBPS} {
			if rate != nil && (*rate < 0 || *rate > 1_000_000_000_000 || *rate > 0 && (*rate < 8192 || *rate%8 != 0)) {
				return nil, fmt.Errorf("VALIDATION_FAILED: profile rate must be 0 or at least 8192 bit/s in multiples of 8")
			}
		}
		if in.LimitBytes != nil && *in.LimitBytes < 0 {
			return nil, fmt.Errorf("VALIDATION_FAILED: negative profile limit")
		}
		name := strings.TrimSpace(in.ClientName)
		if len([]rune(name)) > 120 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("VALIDATION_FAILED: profile name must be at most 120 characters on one line")
		}
		if name != "" {
			profs[i].LabelRU = name
			profs[i].LabelEn = name
		}
		profs[i].LimitBytes = in.LimitBytes
		profs[i].DownloadBPS, profs[i].UploadBPS = in.DownloadBPS, in.UploadBPS
	}
	for _, p := range profs {
		if p.Kind != "transit" || p.RoutePort > 0 {
			continue
		}
		granted := false
		for _, grant := range profs {
			if grant.Kind == "transit" && grant.RoutePort > 0 && grant.IngressAddr == p.IngressAddr {
				granted = true
				break
			}
		}
		if !granted && !local {
			return nil, fmt.Errorf("VALIDATION_FAILED: policy profile needs at least one transit exit grant on the same ingress")
		}
	}
	return profs, nil
}

func (s *Service) findTransitEdge(st *controlstore.Store, exitID string) (*controlstore.Node, error) {
	links, err := st.ListLinks()
	if err != nil {
		return nil, err
	}
	nodes, err := st.ListNodes()
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		n := &nodes[i]
		if n.Role != "ru" || n.RevokedAt != nil || n.IngressAddr == "" {
			continue
		}
		for _, l := range links {
			if l.EdgeID == n.ID && l.ExitID == exitID {
				return n, nil
			}
		}
	}
	return nil, fmt.Errorf("VALIDATION_FAILED: no RU ingress edge linked to exit %s (transit profile needs an active edge→exit link)", exitID)
}

// SubscriptionSetProfiles updates the catalog (live: the next fetch sees it).
func (s *Service) SubscriptionSetProfiles(subID string, inputs []SubscriptionInput) error {
	st, err := s.OpenControlStore()
	if err != nil {
		return err
	}
	defer st.Close()
	return s.subscriptionApplyProfiles(st, subID, inputs)
}

// SubscriptionCatalogView is the public fetch payload: labeled profiles
// with REAL client configs; no secrets beyond the client's own profile
// UUID (it is the client's credential by design, same as a config export).
func (s *Service) SubscriptionCatalogView(sub *controlstore.Subscription, profs []controlstore.SubscriptionProfile, uuid, sni string, caPath string) (map[string]any, error) {
	entries := []map[string]any{}
	for _, p := range profs {
		addr := p.IngressAddr
		// B23: transit profiles use their DEDICATED route port — DE and NL
		// through one RU ingress are distinct wire endpoints, so the
		// executable client config genuinely differs per exit choice.
		if p.RoutePort > 0 {
			if host, _, err := net.SplitHostPort(p.IngressAddr); err == nil {
				addr = net.JoinHostPort(host, strconv.Itoa(p.RoutePort))
			}
		}
		sniForProfile := p.SNI
		if sniForProfile == "" {
			sniForProfile = sni
		}
		cp := clientengine.Profile{
			ServerAddr: addr, ServerName: sniForProfile, CAPath: caPath,
			UUID: uuid, TUNName: "ara-tun", TUNAddr4: "10.99.0.1/30", MTU: 1400,
		}
		cfg, err := clientengine.ConfigFor(cp)
		if err != nil {
			return nil, err
		}
		entries = append(entries, map[string]any{
			"seq": p.Seq, "label_ru": p.LabelRU, "label_en": p.LabelEn,
			"kind": p.Kind, "node_id": p.NodeID, "protocol": p.Protocol,
			"client_config": cfg,
		})
	}
	return map[string]any{
		"schema": "ara.subscription/v1", "subscription_id": sub.ID,
		"name": sub.Name, "owner_panel": sub.OwnerPanel,
		"limits_bytes": sub.LimitsBytes, "profiles": entries,
		"generated_at": time.Now().UTC(),
	}, nil
}

// ---- federation client ----

// FedCall performs a signed federation request to another panel. The
// caller supplies the target base URL; scopes are enforced server-side.
type FedCall struct {
	Base  string
	Ident *fedauth.Identity
	HTTP  *http.Client
}

// NewFedCall builds a federation client (B44): redirects are refused —
// a panel endpoint never delegates via HTTP 3xx, so the signed request
// and its administrative payload cannot be forwarded to another origin.
// HTTP bases are allowed only when explicitly listed (lab scope).
// NewFedCall enforces the inter-panel transport contract (B44): HTTPS is
// the ONLY administrative transport; plain HTTP is refused unless the base
// is an explicit LOOPBACK endpoint (lab scope — the operator runs panels
// on one machine). The check happens here AND per request, so a stored
// or redirected base cannot downgrade silently.
func NewFedCall(base string, ident *fedauth.Identity) *FedCall {
	if err := ValidateFedBase(base); err != nil {
		return &FedCall{Base: base, Ident: ident, HTTP: &http.Client{Transport: fedBaseError{err}}}
	}
	return &FedCall{Base: base, Ident: ident, HTTP: &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// fedBaseError refuses every request with the stored contract error.
type fedBaseError struct{ err error }

func (e fedBaseError) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, e.err
}

// ValidateFedBase is the shared base-URL contract for federation,
// redeem, quota and dispatch clients.
func ValidateFedBase(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("VALIDATION_FAILED: federation base URL invalid: %q", base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "127.0.0.1" || h == "localhost" || h == "::1" {
			return nil // explicit loopback/lab scope only
		}
		return fmt.Errorf("VALIDATION_FAILED: federation base must be HTTPS (loopback http allowed only): %q", base)
	default:
		return fmt.Errorf("VALIDATION_FAILED: federation base scheme %q not allowed", u.Scheme)
	}
}

// Do sends method+path+body signed with this panel's identity.
func (c *FedCall) Do(method, path string, payload any) (map[string]any, error) {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = b
	}
	ts := time.Now().Unix()
	nonce := fmt.Sprintf("n-%d", time.Now().UnixNano())
	if err := ValidateFedBase(c.Base); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ARA-Panel", c.Ident.PanelID)
	req.Header.Set("X-ARA-Timestamp", fmt.Sprint(ts))
	req.Header.Set("X-ARA-Nonce", nonce)
	req.Header.Set("X-ARA-Signature", c.Ident.Sign(method, path, ts, nonce, body))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("fed response undecodable (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 400 {
		if msg, _ := out["error"].(string); msg != "" {
			return out, fmt.Errorf("fed %d: %s", resp.StatusCode, msg)
		}
		return out, fmt.Errorf("fed %d", resp.StatusCode)
	}
	return out, nil
}

// PostRedeem sends the one-time federation invite (invite-token
// authenticated; no link exists yet, so no request signature).
func (c *FedCall) PostRedeem(token, panelID, pubKey string) (map[string]any, error) {
	// redeem is authenticated by the one-time invite token, not signed:
	// no link (and no known peer key) exists yet
	return c.doUnsigned("/api/fed/v1/link/redeem", map[string]any{
		"token": token, "panel_id": panelID, "public_key": pubKey,
	})
}

func (c *FedCall) doUnsigned(path string, payload any) (map[string]any, error) {
	b, _ := json.Marshal(payload)
	if err := ValidateFedBase(c.Base); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.Base+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("fed response undecodable (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 400 {
		if msg, _ := out["error"].(string); msg != "" {
			return out, fmt.Errorf("%s", msg)
		}
		return out, fmt.Errorf("fed %d", resp.StatusCode)
	}
	return out, nil
}

// FederationShareTopology publishes the shared nodes to a linked panel:
// only nodes marked shared, with their ingress capability. The remote
// panel stores them as remote entries usable in subscription catalogs.
func (s *Service) FederationShareTopology(panelID, baseURL string) (map[string]any, error) {
	return s.FederationShareSelectedTopology(panelID, baseURL, nil)
}

func (s *Service) FederationShareSelectedTopology(panelID, baseURL string, nodeIDs []string) (map[string]any, error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	_, scopes, err := st.LinkedPanelPubKey(panelID)
	if err != nil || !strings.Contains(","+scopes+",", ",nodes,") {
		return nil, fmt.Errorf("PERMISSION_DENIED: active peer with nodes scope required")
	}
	selected := map[string]bool{}
	for _, id := range nodeIDs {
		selected[id] = true
	}
	nodes, err := st.ListNodes()
	if err != nil {
		return nil, err
	}
	shared := []map[string]any{}
	for _, n := range nodes {
		if n.RevokedAt != nil || n.RemotePanel != "" || (nodeIDs != nil && !selected[n.ID]) {
			continue
		}
		if n.IngressAddr == "" && n.Role != "foreign" {
			continue // exchanges carry ingress nodes and foreign exits only
		}
		shared = append(shared, map[string]any{
			"id": n.ID, "country": n.Country, "role": n.Role,
			"ingress_addr": n.IngressAddr, "sni": n.IngressSNI,
		})
	}
	if nodeIDs != nil && len(shared) != len(selected) {
		return nil, fmt.Errorf("VALIDATION_FAILED: choose active locally owned nodes with ingress or exit capability")
	}
	fc := NewFedCall(baseURL, s.PanelIdentity())
	return fc.Do(http.MethodPost, "/api/fed/v1/topology/import", map[string]any{"nodes": shared})
}

// FederationRevokeLink tears the link down locally FIRST (fail-closed),
// then best-effort notifies the remote panel. Audit happens at the caller.
func (s *Service) FederationRevokeLink(panelID, baseURL string) error {
	st, err := s.OpenControlStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.RevokeLinkedPanel(panelID); err != nil {
		return err
	}
	fc := NewFedCall(baseURL, s.PanelIdentity())
	if _, err := fc.Do(http.MethodPost, "/api/fed/v1/link/revoke", map[string]any{"panel_id": s.PanelID()}); err != nil {
		// local revocation already stands: the remote notice is advisory
		return fmt.Errorf("link revoked locally; remote notice failed: %w", err)
	}
	return nil
}

// SubscriptionTransfer moves the subscription (with usage, limits, token)
// to another panel under a DURABLE 4-phase protocol (no dual authority,
// no spend loss, retry-safe after any crash/lost response):
//
//	prepare:  durable migration row (snapshot used) — the source remains
//	          the ONLY authority while the migration exists;
//	import:   target stores an INACTIVE copy (active=0) with the SAME id,
//	          token hash, limits, device state and rate — idempotent by
//	          migration id;
//	flip:     ONE transaction snapshots the final usage (INCLUDING the
//	          outstanding offline lease obligations) and switches
//	          owner_panel + commits the migration (FED06 atomicity);
//	activate: target applies the final usage delta and becomes
//	          authoritative; the migration is marked activated.
//
// Retry semantics (FED06): a durably COMMITTED migration is recognized
// BEFORE the ordinary owner check — the same command resumes with exactly
// one activate call; after the activation is recorded the retry is a
// durable no-op (the target is never re-imported into inactivity).
func (s *Service) SubscriptionTransfer(subID, targetPanelID, targetBaseURL string) error {
	st, err := s.OpenControlStore()
	if err != nil {
		return err
	}
	defer st.Close()
	sub, err := st.GetSubscription(subID)
	if err != nil {
		return err
	}
	if sub.RevokedAt != nil {
		return fmt.Errorf("VALIDATION_FAILED: subscription %s is revoked", subID)
	}
	// 1. durable migration state FIRST: a committed migration from a
	// previous run resumes regardless of who owns the row now (the flip
	// already moved it on the source)
	migID, migState, migFinal, err := st.FindLatestMigration(subID, targetPanelID)
	if err != nil {
		return err
	}
	if migID != "" && migState != "prepared" && sub.OwnerPanel != s.PanelID() {
		// flip already happened on this source: resume activation only
		return s.resumeTransferActivation(st, sub, migID, migState, migFinal, targetPanelID, targetBaseURL)
	}
	if sub.OwnerPanel != s.PanelID() {
		return fmt.Errorf("CONFLICT: panel %s is not the owner of %s (owner %s)", s.PanelID(), subID, sub.OwnerPanel)
	}
	// 2. prepare (idempotent: reuse an existing prepared migration)
	snapshotUsed, _, err := st.QuotaUsage(subID)
	if err != nil {
		return err
	}
	if migID == "" || migState == "" {
		migrationID := NewPlanID("mig")
		if err := st.CreateMigration(migrationID, subID, s.PanelID(), targetPanelID, snapshotUsed); err != nil {
			return err
		}
		migID, migState = migrationID, "prepared"
	}
	// 3. import on the target (idempotent; the copy is INACTIVE there)
	profs, err := st.ListSubscriptionProfiles(subID)
	if err != nil {
		return err
	}
	devUsage, devLimits, rd, ru, err := st.LoadSubscriptionTransferState(subID)
	if err != nil {
		return err
	}
	devices, err := st.LoadAccountDevices(sub.AccountID)
	if err != nil {
		return err
	}
	var tokenHash string
	if err := st.QueryRow("SELECT token_hash FROM subscriptions WHERE id=?", subID, &tokenHash); err != nil {
		return err
	}
	export := *sub
	export.UsedBytes = snapshotUsed
	export.OwnerPanel = "" // the TARGET assigns itself (review finding)
	export.Active = nil
	export.DeviceUsage = devUsage
	export.DeviceLimits = devLimits
	export.RateDownBPS = rd
	export.RateUpBPS = ru
	fc := NewFedCall(targetBaseURL, s.PanelIdentity())
	ack, err := fc.Do(http.MethodPost, "/api/fed/v1/subscription/import", map[string]any{
		"subscription": &export, "profiles": profs, "used_bytes": snapshotUsed,
		"token_hash": tokenHash, "migration_id": migID, "source_panel": s.PanelID(),
		"devices": devices,
	})
	if err != nil {
		return fmt.Errorf("import on target panel failed: %w", err)
	}
	for _, p := range profs {
		if p.LimitBytes != nil && ack["profile_budgets_supported"] != true {
			return fmt.Errorf("CONFLICT: target does not support profile budgets")
		}
	}
	if (export.MaxDevices != nil || len(devUsage) != 0 || len(devLimits) != 0 || rd != nil || ru != nil) && ack["limits_persisted"] != true {
		return fmt.Errorf("CONFLICT: target did not acknowledge persisted subscription limits; upgrade the target panel before transfer")
	}
	if export.MaxDevices != nil && ack["max_devices"] != float64(*export.MaxDevices) {
		return fmt.Errorf("CONFLICT: target did not acknowledge the device slot limit")
	}
	fetchBase := strings.TrimRight(targetBaseURL, "/")
	if advertised, _ := ack["subscription_base"].(string); advertised != "" {
		u, err := subscriptionFetchBase(advertised)
		if err != nil || (strings.HasPrefix(targetBaseURL, "https://") && u.Scheme != "https") {
			return fmt.Errorf("CONFLICT: invalid destination subscription endpoint")
		}
		fetchBase = advertised
	}
	// 4. flip: ONE atomic transaction (final usage incl. lease obligations
	// + owner switch + migration commit)
	if migState == "prepared" {
		finalUsed, err := st.FlipSubscriptionToTarget(migID, subID, targetPanelID, 0, fetchBase)
		if err != nil {
			return err
		}
		migFinal = &finalUsed
	}
	if migFinal == nil {
		fu, _, err := st.QuotaUsage(subID)
		if err != nil {
			return err
		}
		migFinal = &fu
	}
	// 5. activate on the target (retry until confirmed; idempotent)
	return s.resumeTransferActivation(st, sub, migID, "committed", migFinal, targetPanelID, targetBaseURL)
}

// resumeTransferActivation sends the activate call (once per invocation)
// and marks the migration activated on success; a repeated retry after
// that is a durable no-op.
func (s *Service) resumeTransferActivation(st *controlstore.Store, sub *controlstore.Subscription, migID, migState string, migFinal *int64, targetPanelID, targetBaseURL string) error {
	if migState == "activated" {
		return nil // durable no-op
	}
	if migFinal == nil {
		fu, _, err := st.QuotaUsage(sub.ID)
		if err != nil {
			return err
		}
		migFinal = &fu
	}
	profileSpends, err := st.ProfileSpends(sub.ID)
	if err != nil {
		return err
	}
	fc := NewFedCall(targetBaseURL, s.PanelIdentity())
	if _, err := fc.Do(http.MethodPost, "/api/fed/v1/subscription/activate", map[string]any{
		"migration_id": migID, "subscription_id": sub.ID,
		"final_used": *migFinal, "source_panel": s.PanelID(), "profile_spends": profileSpends,
	}); err != nil {
		return fmt.Errorf("CONFLICT: transfer committed on the source; activation of the target pending — retry the same command to finish it: %w", err)
	}
	return st.MarkMigrationActivated(migID)
}

// dbExec runs one raw statement through the store (narrow escape hatch
// for cross-table updates owned by the service layer).
func (s *Service) dbExec(st *controlstore.Store, q string, args ...any) (any, error) {
	return st.Exec(q, args...)
}

// SubscriptionRotateToken is the operator-facing rotation: generates the
// crypto-random secret, stores only the hash (CAS from the current row —
// the operator acts with panel authority), returns the secret ONCE.
// Audit happens at the API layer without the secret.
func (s *Service) SubscriptionRotateToken(subID string, grace time.Duration) (token string, graceSeconds int, err error) {
	st, err := s.OpenControlStore()
	if err != nil {
		return "", 0, err
	}
	defer st.Close()
	// B08: only the AUTHORITATIVE owner panel rotates the fetch token —
	// a transferred-away or imported-pending local copy is refused, so a
	// stale/foreign copy can never mint credentials for the subscription.
	sub, err := st.GetSubscription(subID)
	if err != nil {
		return "", 0, err
	}
	if sub.OwnerPanel != s.PanelID() {
		return "", 0, fmt.Errorf("CONFLICT: panel %s is not the owner of %s (owner %s)", s.PanelID(), subID, sub.OwnerPanel)
	}
	if sub.RevokedAt != nil {
		return "", 0, fmt.Errorf("AUTH_FAILED: subscription revoked")
	}
	secret, err := controlstore.RandomSecret(24)
	if err != nil {
		return "", 0, err
	}
	// CAS from the hash we just read: a concurrent transfer/revoke between
	// the check and the swap fails the rotation instead of overwriting.
	var curHash string
	if err := st.QueryRow("SELECT token_hash FROM subscriptions WHERE id=?", subID, &curHash); err != nil {
		return "", 0, err
	}
	res, err := st.RotateSubscriptionToken(subID, curHash, controlstore.HashToken(secret), grace)
	if err != nil {
		return "", 0, err
	}
	return secret, res.GraceSeconds, nil
}

// SubscriptionCatalogViewPerSNI renders the catalog honoring EACH
// profile's own ingress SNI (B24): profiles for different ingress nodes
// carry their own hostnames instead of one global panel SNI.
func (s *Service) SubscriptionCatalogViewPerSNI(sub *controlstore.Subscription, profs []controlstore.SubscriptionProfile, uuid, caPath string) (map[string]any, error) {
	// B24: each profile carries its OWN ingress SNI (per-ingress TLS).
	return s.SubscriptionCatalogView(sub, profs, uuid, "", caPath)
}

// RoutePortHashBase re-exports the controlstore derivation (C04): the
// route port is a function of the route identity only.
func RoutePortHashBase(nodeID string) int { return controlstore.RoutePortHashBase(nodeID) }

// RoutePortForExit derives the deterministic dedicated access port for a
// transit route (B23/C04): stable per exit id — equal priorities never
// collide by construction, a priority change never reshuffles ports, and
// adding DE cannot move NL (index-of-sorted-set was the C04 defect).
func RoutePortForExit(edgeExits []string, nodeID string) (int, error) {
	for _, id := range edgeExits {
		if id == nodeID {
			p := RoutePortHashBase(nodeID)
			if p > 65535 {
				return 0, fmt.Errorf("VALIDATION_FAILED: route port space exhausted")
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("VALIDATION_FAILED: node %s is not an exit of this edge", nodeID)
}
