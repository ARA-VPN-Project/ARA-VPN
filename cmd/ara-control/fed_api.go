package main

// Federation API (docs/FEDERATION.md): /api/fed/v1/* endpoints verify the
// Ed25519-signed request against the LINKED panel table (limited scopes,
// fresh timestamp+nonce); the configured subscription path serves the multi-profile
// subscription catalog publicly (token = bearer credential of the user).
// The owner panel is the ONLY authority for subscription state: delegates
// receive NOT_OWNER, and revocation propagates through the quota/report
// refusal to serving nodes.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"aravpn/core/fedauth"
	"aravpn/internal/controlstore"
	"aravpn/internal/transport"
)

// store2 is the already-open control store (alias for readability).
func (s *server) store2() (*controlstore.Store, error) { return s.store, nil }

// panelIdentity is the panel key loaded at startup.
func (s *server) panelIdentity() *fedauth.Identity { return s.panelIdent }

// readBody reads a bounded body; on error it has already responded.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) []byte {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED: body"}`, http.StatusBadRequest)
		return nil
	}
	return b
}

// verifyFed authenticates a signed federation request. Returns panel id,
// scopes, ok.
func (s *server) verifyFed(w http.ResponseWriter, r *http.Request, body []byte) (string, string, bool) {
	panelID := r.Header.Get("X-ARA-Panel")
	ts := parseI64(r.Header.Get("X-ARA-Timestamp"))
	nonce := r.Header.Get("X-ARA-Nonce")
	sig := r.Header.Get("X-ARA-Signature")
	if panelID == "" {
		http.Error(w, `{"error":"AUTH_FAILED: panel header missing"}`, http.StatusUnauthorized)
		return "", "", false
	}
	st, err := s.store2()
	if err != nil {
		http.Error(w, `{"error":"INTERNAL"}`, http.StatusInternalServerError)
		return "", "", false
	}
	pub, scopes, err := st.LinkedPanelPubKey(panelID)
	if err != nil {
		http.Error(w, `{"error":"AUTH_FAILED: panel not linked"}`, http.StatusUnauthorized)
		return "", "", false
	}
	if err := fedauth.Verify(pub, r.Method, r.URL.Path, ts, nonce, sig, body, time.Now()); err != nil {
		http.Error(w, `{"error":"AUTH_FAILED: `+err.Error()+`"}`, http.StatusUnauthorized)
		return "", "", false
	}
	return panelID, scopes, true
}

func parseI64(sv string) int64 {
	var v int64
	_, _ = fmt.Sscan(sv, &v)
	return v
}

// handleFedLinkRedeem consumes the one-time invite (token = auth) and
// registers the requesting panel with its public key.
func (s *server) handleFedLinkRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token   string `json:"token"`
		PanelID string `json:"panel_id"`
		PubKey  string `json:"public_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	scopes, err := s.store.RedeemLinkInvite(req.Token, req.PanelID, req.PubKey)
	if err != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "fed.link.redeem", ObjectID: req.PanelID, Result: "denied"})
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "fed.link.redeem", ObjectID: req.PanelID, Result: "ok", Detail: "scopes=" + scopes})
	id := s.panelIdentity()
	writeJSON(w, http.StatusOK, map[string]any{
		"panel_id": id.PanelID, "public_key": id.PublicHex(), "scopes": scopes,
	})
}

// handleFedTopologyImport stores federation-shared nodes (limited to the
// panels the operator linked; scope "nodes").
func (s *server) handleFedTopologyImport(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 64<<10)
	if body == nil {
		return
	}
	panelID, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	if !scopeHas(scopes, "nodes") {
		http.Error(w, `{"error":"PERMISSION_DENIED: scope nodes required"}`, http.StatusForbidden)
		return
	}
	var req struct {
		Nodes []struct {
			ID          string `json:"id"`
			Country     string `json:"country"`
			Role        string `json:"role"`
			IngressAddr string `json:"ingress_addr"`
			SNI         string `json:"sni"`
			Priority    int    `json:"priority"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	st, _ := s.store2()
	imported := 0
	for _, n := range req.Nodes {
		err := st.UpsertRemoteNode(&controlstore.Node{
			ID: n.ID, Country: n.Country, Role: n.Role, Priority: n.Priority,
			IngressAddr: n.IngressAddr, IngressSNI: n.SNI,
		}, panelID)
		if err == nil {
			imported++
		}
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "panel:" + panelID, Action: "fed.topology.import", Result: "ok", Detail: fmt.Sprintf("%d nodes", imported)})
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported})
}

// handleFedSubImport is the target side of an ownership transfer: the
// imported copy is INACTIVE (active=0) until the source's flip is
// confirmed by /api/fed/v1/subscription/activate — no dual authority.
// The target assigns ITSELF as owner explicitly (review finding: the
// payload's owner field is never trusted). Re-import with the same
// migration id updates the pending copy (idempotent retry).
func (s *server) handleFedSubImport(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 256<<10)
	if body == nil {
		return
	}
	panelID, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	if !scopeHas(scopes, "subscriptions") {
		http.Error(w, `{"error":"PERMISSION_DENIED: scope subscriptions required"}`, http.StatusForbidden)
		return
	}
	var req struct {
		Subscription controlstore.Subscription          `json:"subscription"`
		Profiles     []controlstore.SubscriptionProfile `json:"profiles"`
		UsedBytes    int64                              `json:"used_bytes"`
		TokenHash    string                             `json:"token_hash"`
		MigrationID  string                             `json:"migration_id"`
		Devices      []controlstore.MigratedDevice      `json:"devices"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	sub := req.Subscription
	if sub.ID == "" || sub.AccountID == "" || req.TokenHash == "" || req.MigrationID == "" {
		http.Error(w, `{"error":"VALIDATION_FAILED: subscription/token_hash/migration_id required"}`, http.StatusBadRequest)
		return
	}
	st, _ := s.store2()
	if _, err := st.CreateAccount(sub.AccountID, "federation transfer from "+panelID); err != nil {
		_ = err // existing account is fine
	}
	local := s.panelIdentity().PanelID
	// EXPLICIT target owner assignment (never trust the payload)
	sub.OwnerPanel = local
	sub.UsedBytes = req.UsedBytes
	// B05/B06 + product-completion: the imported copy and its migration
	// binding are committed in ONE transaction BEFORE the first mutation.
	// A pending copy belongs to its recorded source: the same source may
	// retry its own migration id (CAS refresh); any other linked peer is
	// refused without touching token hash, usage or identity.
	endpoint, err := s.subscriptionEndpoint()
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := st.PrepareSubscriptionImport(&sub, req.TokenHash, req.Profiles, req.Devices, req.MigrationID, panelID, req.UsedBytes); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	if s.audit != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: "panel:" + panelID, Action: "fed.subscription.import", ObjectID: sub.ID, Result: "ok",
			Detail: fmt.Sprintf("migration=%s used_bytes=%d preserved (inactive until activate)", req.MigrationID, req.UsedBytes)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": sub.ID, "owner": local,
		"active": false, "used_bytes_preserved": req.UsedBytes, "profile_budgets_supported": true, "limits_persisted": true, "max_devices": sub.MaxDevices, "subscription_base": endpoint.Base()})
}

// handleFedSubActivate flips the imported copy to the authoritative one,
// applying the FINAL usage delta from the source. Idempotent.
func (s *server) handleFedSubActivate(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 16<<10)
	if body == nil {
		return
	}
	panelID, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	if !scopeHas(scopes, "subscriptions") {
		http.Error(w, `{"error":"PERMISSION_DENIED: scope subscriptions required"}`, http.StatusForbidden)
		return
	}
	var req struct {
		MigrationID    string                               `json:"migration_id"`
		SubscriptionID string                               `json:"subscription_id"`
		FinalUsed      int64                                `json:"final_used"`
		ProfileSpends  map[string]controlstore.ProfileSpend `json:"profile_spends"`
	}
	if err := json.Unmarshal(body, &req); err != nil || (req.MigrationID == "" && req.SubscriptionID == "") {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	st, _ := s.store2()
	// B06: activation is driven ONLY by the migration record — the record
	// binds (source, target, subscription) and must exist, match the
	// declared subscription, and name the REQUESTING panel as its source.
	// An explicit subscription_id without a matching migration is refused;
	// a linked peer with a fake migration id can never activate.
	mig, merr := st.GetMigration(req.MigrationID)
	if merr != nil {
		http.Error(w, `{"error":"AUTH_FAILED: unknown or unbound migration"}`, http.StatusUnauthorized)
		return
	}
	if req.SubscriptionID != "" && req.SubscriptionID != mig.SubID {
		http.Error(w, `{"error":"AUTH_FAILED: migration/subscription mismatch"}`, http.StatusUnauthorized)
		return
	}
	if mig.FromPanel != panelID {
		http.Error(w, `{"error":"AUTH_FAILED: activation driver is not the recorded source owner"}`, http.StatusUnauthorized)
		return
	}
	subID := mig.SubID
	if err := st.ActivateImportedSubscription(subID, req.FinalUsed, req.ProfileSpends); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	if s.audit != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: "panel:" + panelID, Action: "fed.subscription.activate", ObjectID: subID, Result: "ok",
			Detail: fmt.Sprintf("migration=%s final_used=%d", req.MigrationID, req.FinalUsed)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"activated": subID, "final_used": req.FinalUsed})
}

// handleFedQuotaReport applies usage to the AUTHORITATIVE owner ledger.
// Idempotency (review FED02): the mutation runs INSIDE WithFedOpTx keyed
// by the client's stable op_id (preferred) or panel+nonce — a replayed
// request (same signature/nonce or retried op) returns the recorded
// response without re-charging. A legitimate retry with a NEW nonce but
// the SAME op_id is also replayed (exactly-once per logical operation).
func (s *server) handleFedQuotaReport(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 16<<10)
	if body == nil {
		return
	}
	panelID, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	_ = panelID
	if !scopeHas(scopes, "quota") {
		http.Error(w, `{"error":"PERMISSION_DENIED: scope quota required"}`, http.StatusForbidden)
		return
	}
	var req struct {
		SubscriptionID   string `json:"subscription_id"`
		DeviceID         string `json:"device_id"`
		UsedBytes        int64  `json:"used_bytes"`
		ReserveBytes     int64  `json:"reserve_bytes"`
		RUBytes          int64  `json:"ru_bytes"`
		ForeignBytes     int64  `json:"foreign_bytes"`
		ActivityOnly     bool   `json:"activity_only"`
		AccessCheck      bool   `json:"access_check"`
		ActivityAt       int64  `json:"activity_at"`
		SeparateActivity bool   `json:"separate_activity"`
		OpID             string `json:"op_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.SubscriptionID == "" {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	// B05: quota scope proves IDENTITY, not authority over every local
	// subscription — the reporting edge must be a REGISTERED serving edge
	// for THIS subscription (per-object delegation granted at
	// edge-config apply), checked before any bookkeeping.
	stAuth, _ := s.store2()
	if !stAuth.EdgeSubscriptionDelegated(panelID, req.SubscriptionID) {
		http.Error(w, `{"error":"PERMISSION_DENIED: this edge is not a registered serving edge for the subscription"}`, http.StatusForbidden)
		return
	}
	st, _ := s.store2()
	sub, err := st.GetSubscription(req.SubscriptionID)
	if err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED: unknown subscription"}`, http.StatusNotFound)
		return
	}
	if sub.OwnerPanel != s.panelIdentity().PanelID {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "NOT_OWNER", "owner": sub.OwnerPanel,
			"transferred_to": sub.TransferredTo})
		return
	}
	// B02/interim: the STABLE operation identity is (panel, subscription,
	// op_id); the digest of the content is stored with the op record.
	// Exact retry returns the recorded response; the same identity with a
	// different body is a CONFLICT without any new effect.
	content := fmt.Sprintf("%s|%s|%d|%d", req.DeviceID, req.OpID, req.UsedBytes, req.ReserveBytes)
	if req.RUBytes != 0 || req.ForeignBytes != 0 {
		content += fmt.Sprintf("|%d|%d", req.RUBytes, req.ForeignBytes)
	}
	if req.ActivityOnly || req.SeparateActivity {
		content += fmt.Sprintf("|%t|%t|%d", req.ActivityOnly, req.SeparateActivity, req.ActivityAt)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	scope := "op:" + panelID + ":" + req.SubscriptionID + ":" + req.OpID
	if req.OpID == "" {
		scope = "nonce:" + panelID + ":" + r.Header.Get("X-ARA-Nonce")
	}
	opKey := scope
	// the edge prefixes its panel id itself; normalize to exactly one
	holder := req.DeviceID
	if !strings.HasPrefix(holder, panelID+"|") {
		holder = panelID + "|" + holder
	}
	if req.ActivityOnly {
		if req.OpID == "" || req.ReserveBytes != 0 || sub.RevokedAt != nil ||
			(sub.Active != nil && !*sub.Active) || (sub.ExpiresAt != nil && !time.Now().Before(*sub.ExpiresAt)) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "ACTIVITY_DENIED"})
			return
		}
		device := holder[strings.LastIndex(holder, "|")+1:]
		if req.AccessCheck && req.UsedBytes == 0 && req.RUBytes == 0 && req.ForeignBytes == 0 {
			expires, err := st.SubscriptionDeviceAccess(req.SubscriptionID, device)
			if errors.Is(err, controlstore.ErrDeviceAccess) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "DEVICE_ACCESS_DENIED"})
			} else if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "UNAVAILABLE"})
			} else {
				writeJSON(w, http.StatusOK, map[string]any{"access_checked": true, "device_expires_unix": expires})
			}
			return
		}
		err := st.ReportSubscriptionActivity(opKey, digest, req.SubscriptionID, device, req.ActivityAt, req.UsedBytes, req.RUBytes, req.ForeignBytes)
		switch {
		case errors.Is(err, controlstore.ErrDeviceAccess), errors.Is(err, controlstore.ErrActivityExpired):
			writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		default:
			writeJSON(w, http.StatusOK, map[string]any{"activity_accepted": true})
		}
		return
	}
	resp, replayed, err := st.QuotaReportRouted(opKey, digest, req.SubscriptionID, holder, req.UsedBytes, req.ReserveBytes, req.RUBytes, req.ForeignBytes, !req.SeparateActivity)
	if err != nil {
		if errors.Is(err, controlstore.ErrDeviceAccess) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "DEVICE_ACCESS_DENIED"})
			return
		}
		msg := err.Error()
		if strings.Contains(msg, "revoked") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": msg})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	if !replayed && s.audit != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: "panel:" + panelID, Action: "fed.quota.report",
			ObjectID: req.SubscriptionID, Result: "ok",
			Detail: fmt.Sprintf("used=%d granted=%d op=%s", req.UsedBytes, resp.Granted, req.OpID)})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleFedEdgeConfig is the signed config dispatch: the serving edge
// pulls its latest applied config (hash-first check on the client).
func (s *server) handleFedEdgeConfig(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 1<<10)
	if body == nil {
		body = []byte{}
	}
	panelID, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	_ = panelID
	if !scopeHas(scopes, "nodes") {
		http.Error(w, `{"error":"PERMISSION_DENIED: scope nodes required"}`, http.StatusForbidden)
		return
	}
	st, _ := s.store2()
	cj, hash, err := st.EdgeConfigFor(panelID)
	if err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED: no config published for this edge"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config_hash": hash, "config_raw": cj})
}

// handleFedLinkRevoke is the remote side of a teardown.
func (s *server) handleFedLinkRevoke(w http.ResponseWriter, r *http.Request) {
	body := readBody(w, r, 8<<10)
	if body == nil {
		return
	}
	panelID, _, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	if err := s.store.RevokeLinkedPanel(panelID); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"already": true})
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "panel:" + panelID, Action: "fed.link.revoke", ObjectID: panelID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": panelID})
}

// handleSubFetch serves only the currently configured public service path.
func (s *server) handleSubFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	e, err := s.subscriptionEndpoint()
	if err != nil {
		http.Error(w, `{"error":"UNAVAILABLE"}`, http.StatusServiceUnavailable)
		return
	}
	if r.PathValue("subscription_service") != e.Name || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	token := r.PathValue("subscription_token")
	if token == "" || len(token) > 128 {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	st, err := s.store2()
	if err != nil {
		http.Error(w, `{"error":"INTERNAL"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	sub, _, ferr := st.FindSubscriptionByTokenWithGrace(token)
	deviceID := ""
	if ferr != nil {
		sub, deviceID, ferr = st.FindSubscriptionDeviceLink(token)
	}
	if ferr != nil || sub.RevokedAt != nil || (sub.ExpiresAt != nil && !time.Now().Before(*sub.ExpiresAt)) {
		http.Error(w, `{"error":"AUTH_FAILED: subscription token is invalid, expired or revoked"}`, http.StatusUnauthorized)
		return
	}
	if sub.TransferredTo != "" && sub.OwnerPanel != s.panelIdentity().PanelID {
		// ownership moved: a notice, not a second authority. fetch_base is
		// the base recorded by THIS panel at transfer time — the client
		// validates the destination independently before following.
		fb, _ := st.SubscriptionFetchBase(sub.ID)
		writeJSON(w, http.StatusOK, map[string]any{"schema": "ara.subscription/v1",
			"moved": true, "owner_panel": sub.OwnerPanel, "transferred_to": sub.TransferredTo,
			"fetch_base": fb})
		return
	}
	if sub.Active != nil && !*sub.Active {
		// imported-pending: an authority exists elsewhere; never serve a
		// half-transferred catalog
		writeJSON(w, http.StatusConflict, map[string]any{"schema": "ara.subscription/v1",
			"transfer_pending": true, "owner_panel": sub.OwnerPanel})
		return
	}
	profs, err := st.ListSubscriptionProfiles(sub.ID)
	if err != nil {
		http.Error(w, `{"error":"INTERNAL"}`, http.StatusInternalServerError)
		return
	}
	// the client profile UUID comes from the subscription's account device
	uuid, err := st.SubscriptionDeviceUUID(sub.ID, deviceID, time.Now())
	if err != nil {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	ua := strings.ToLower(r.UserAgent())
	format := r.URL.Query().Get("format")
	if format == "links" || format == "" && (strings.Contains(ua, "shadowrocket") ||
		strings.Contains(ua, "hiddify") || strings.HasPrefix(ua, "happ") || strings.HasPrefix(ua, "incy")) {
		if uuid == "" || os.Getenv("ARA_SUB_CA") != "system" {
			http.Error(w, "No exportable device or public TLS trust", http.StatusConflict)
			return
		}
		protocol := r.URL.Query().Get("protocol")
		if protocol == "" {
			protocol = "vless"
		}
		if protocol != "vless" && (protocol != "trojan" || !localTrojanEnabled()) {
			http.Error(w, "Unsupported ingress protocol", http.StatusBadRequest)
			return
		}
		var links []string
		for _, profile := range profs {
			host, port, splitErr := net.SplitHostPort(profile.IngressAddr)
			if splitErr != nil || profile.Protocol != "vless" || profile.SNI == "" {
				continue
			}
			if profile.RoutePort != 0 {
				port = strconv.Itoa(profile.RoutePort)
			}
			q := url.Values{"security": {"tls"}, "type": {"tcp"}, "encryption": {"none"}, "sni": {profile.SNI}}
			credential := uuid
			if protocol == "trojan" {
				credential = transport.TrojanPassword(uuid)
				q.Del("encryption")
			}
			link := url.URL{Scheme: protocol, User: url.User(credential), Host: net.JoinHostPort(host, port), RawQuery: q.Encode(), Fragment: profile.LabelRU}
			links = append(links, link.String())
		}
		if len(links) == 0 {
			http.Error(w, "No exportable profiles", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Vary", "User-Agent")
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
		return
	}
	w.Header().Add("Vary", "User-Agent")
	caPath := os.Getenv("ARA_SUB_CA")
	switch caPath {
	case "":
		caPath = "/etc/ara/ca.crt"
	case "system":
		// Public-CA deployments use each client's own trust store.
		caPath = ""
	}
	// B24: SNI is PER PROFILE (each ingress node's own hostname); the
	// global panel SNI is only the fallback when a profile has none.
	svc, _ := s.service()
	for i := range profs {
		if profs[i].SNI == "" {
			profs[i].SNI = os.Getenv("ARA_SUB_SNI")
			if profs[i].SNI == "" {
				profs[i].SNI = "edge.ara.lab"
			}
		}
	}
	view, err := svc.SubscriptionCatalogViewPerSNI(sub, profs, uuid, caPath)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func scopeHas(scopes, want string) bool {
	for _, p := range splitComma(scopes) {
		if p == want || p == "*" {
			return true
		}
	}
	return false
}

func splitComma(sv string) []string {
	var out []string
	cur := ""
	for _, c := range sv {
		if c == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
