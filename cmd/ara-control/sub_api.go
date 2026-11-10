package main

// Admin-side federation and subscription endpoints (operator token or
// panel session): create link invites, view links, manage subscriptions.
// The same service layer serves the CLI — panel and CLI cannot drift.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"aravpn/core/qrencode"
	"aravpn/internal/controlstore"
	"aravpn/internal/service"
)

// handlePanelInvites creates a one-time federation invite.
func (s *server) handlePanelInvites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		InvitedPanel string `json:"invited_panel"`
		Scopes       string `json:"scopes"` // comma-separated: nodes,subscriptions,quota
		TTLSeconds   int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if req.Scopes == "" {
		req.Scopes = "nodes,subscriptions,quota"
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = 1 * time.Hour
	}
	tok, err := s.store.CreateLinkInvite(req.InvitedPanel, req.Scopes, ttl)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "fed.invite.create", ObjectID: req.InvitedPanel, Result: "ok", Detail: "scopes=" + req.Scopes})
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "scopes": req.Scopes,
		"redeem": "POST /api/fed/v1/link/redeem on THIS panel", "ttl_seconds": int(ttl.Seconds())})
}

func (s *server) handlePanelLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	links, err := s.store.ListLinkedPanels()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "panel_id": s.panelIdentity().PanelID})
}

func (s *server) handlePanelRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Base  string `json:"base"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "VALIDATION_FAILED"})
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := svc.PanelRedeem(req.Base, req.Token)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "fed.link.redeem", Result: "ok"})
	writeJSON(w, http.StatusOK, result)
}

func (s *server) localServingRoutes() map[string]int {
	if os.Getenv("ARA_REQUIRE_SERVING_ROUTES") != "1" {
		return nil
	}
	observation, err := readEdgeObservation(s.edgeStatusPath, time.Now())
	if err != nil || observation.RoutePorts == nil {
		return map[string]int{}
	}
	if path := os.Getenv("ARA_ROUTE_READY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		var configured map[string]int
		if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &configured) != nil {
			return map[string]int{}
		}
		for id, port := range observation.RoutePorts {
			if configured[id] != port {
				delete(observation.RoutePorts, id)
			}
		}
	}
	return observation.RoutePorts
}

func (s *server) verifyLocalServingRoutes(edge string, inputs []service.SubscriptionInput) error {
	ready := s.localServingRoutes()
	if ready == nil {
		return nil
	}
	for _, p := range inputs {
		if p.Kind != "transit" {
			continue
		}
		port, ok := s.store.RoutePortOf(edge, p.NodeID)
		if !ok || ready[p.NodeID] != port {
			return fmt.Errorf("CONFLICT: route %s is not serving yet", p.NodeID)
		}
	}
	return nil
}

// handleSubscriptions: GET list; POST create (with catalog inputs).
func (s *server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, _ := s.store2()
		subs, err := st.ListSubscriptions()
		if err != nil {
			writeErr(w, err)
			return
		}
		type subscriptionView struct {
			controlstore.Subscription
			UsageAvailable bool        `json:"usage_available"`
			LocalUsage     *localUsage `json:"local_usage,omitempty"`
		}
		views := make([]subscriptionView, 0, len(subs))
		live := s.localUsageSnapshot()
		var localBytes map[string]map[string]int64
		if live != nil {
			localBytes, _ = st.LocalTrafficUsage(time.Now())
		}
		for _, sub := range subs {
			view := subscriptionView{Subscription: sub}
			if sub.OwnerPanel == s.panelIdentity().PanelID && sub.TransferredTo == "" && (sub.Active == nil || *sub.Active) {
				used, _, err := st.QuotaUsage(sub.ID)
				if err == nil {
					view.DeviceUsage, view.DeviceLimits, view.RateDownBPS, view.RateUpBPS, err = st.LoadSubscriptionTransferState(sub.ID)
				}
				if err == nil {
					view.UsedBytes, view.UsageAvailable = used, true
				}
			}
			if usage, ok := live[sub.ID]; ok {
				if bytes := localBytes[sub.ID]; bytes != nil {
					view.DeviceUsage = bytes
					if sub.LimitsBytes == nil {
						usage.UsedBytes = 0
						for _, n := range bytes {
							usage.UsedBytes += n
						}
					}
				}
				view.LocalUsage = &usage
				view.UsedBytes = usage.UsedBytes
			}
			views = append(views, view)
		}
		writeJSON(w, http.StatusOK, map[string]any{"subscriptions": views, "local_edge": os.Getenv("ARA_LOCAL_SUB_EDGE"), "ru_only": localSubscriptionRUPort() != 0, "trojan": localTrojanEnabled(), "ready_routes": s.localServingRoutes()})
	case http.MethodPost:
		var req struct {
			AccountID   string `json:"account_id"`
			Name        string `json:"name"`
			LimitsBytes *int64 `json:"limits_bytes"`
			MaxDevices  *int   `json:"max_devices"`
			TTLSeconds  int    `json:"ttl_seconds"`
			Profiles    []struct {
				Kind        string `json:"kind"`
				NodeID      string `json:"node_id"`
				EdgeNodeID  string `json:"edge_node_id"`
				DownloadBPS *int64 `json:"download_bps"`
				UploadBPS   *int64 `json:"upload_bps"`
			} `json:"profiles"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		inputs := make([]service.SubscriptionInput, 0, len(req.Profiles))
		for _, p := range req.Profiles {
			inputs = append(inputs, service.SubscriptionInput{Kind: p.Kind, NodeID: p.NodeID, EdgeNodeID: p.EdgeNodeID, DownloadBPS: p.DownloadBPS, UploadBPS: p.UploadBPS})
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		endpoint, err := s.subscriptionEndpoint()
		if err != nil {
			writeErr(w, err)
			return
		}
		var sub *controlstore.Subscription
		var token string
		if edge := os.Getenv("ARA_LOCAL_SUB_EDGE"); edge != "" {
			if err := s.verifyLocalServingRoutes(edge, inputs); err != nil {
				writeErr(w, err)
				return
			}
			sub, token, err = svc.ProvisionLocalSubscription(req.AccountID, req.Name, req.LimitsBytes, ttl, inputs, req.MaxDevices, edge, localSubscriptionRUPort())
		} else {
			sub, token, err = svc.ProvisionSubscription(req.AccountID, req.Name, req.LimitsBytes, ttl, inputs, req.MaxDevices)
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.create", ObjectID: sub.ID, Result: "ok"})
		// the token is shown once (it is the user's credential)
		if err := s.saveSubscriptionLink(sub.ID, token); err != nil {
			log.Print("subscription link vault write failed")
		}
		writeIssuedSubscription(w, http.StatusCreated, endpoint, token, map[string]any{"subscription": sub})
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSubscriptionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	st, _ := s.store2()
	if err := st.RevokeSubscription(req.ID); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

func (s *server) handleSubscriptionDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: invalid subscription request"))
		return
	}
	if err := s.store.HideRevokedSubscription(req.ID, s.panelIdentity().PanelID); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.delete", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"deleted": req.ID})
}

func (s *server) handleSubscriptionQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string          `json:"id"`
		Limit json.RawMessage `json:"limits_bytes"`
	}
	var limit *int64
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil ||
		json.Unmarshal(req.Limit, &limit) != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: limits_bytes must be an integer or null"))
		return
	}
	if err := s.store.SetSubscriptionQuota(req.ID, s.panelIdentity().PanelID, limit); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.quota", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"set": req.ID})
}

// handleSubscriptionRate sets the AUTHORITATIVE shared rate of a
// subscription (nil = unlimited): serving edges receive rate/holders.
func (s *server) handleSubscriptionRate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID      string `json:"id"`
		DownBPS *int64 `json:"download_bps"`
		UpBPS   *int64 `json:"upload_bps"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if os.Getenv("ARA_LOCAL_SUB_EDGE") != "" {
		for _, rate := range []*int64{req.DownBPS, req.UpBPS} {
			if rate != nil && (*rate < 8192 || *rate > 1_000_000_000_000 || *rate%8 != 0) {
				writeErr(w, fmt.Errorf("VALIDATION_FAILED: shared rate must be at least 8192 bit/s in multiples of 8"))
				return
			}
		}
	}
	st, _ := s.store2()
	if err := st.SetSubscriptionRate(req.ID, req.DownBPS, req.UpBPS); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.rate", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"set": req.ID})
}

// handleSubscriptionDeviceLimit sets the AUTHORITATIVE per-device budget.
func (s *server) handleSubscriptionDeviceSlots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID         string `json:"id"`
		MaxDevices *int   `json:"max_devices"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "VALIDATION_FAILED"})
		return
	}
	if err := s.store.SetSubscriptionMaxDevices(req.ID, s.panelIdentity().PanelID, req.MaxDevices); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.device_slots", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"set": req.ID})
}

func (s *server) handleSubscriptionDeviceLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID       string `json:"id"`
		DeviceID string `json:"device_id"`
		Limit    *int64 `json:"limit_bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" {
		http.Error(w, `{"error":"VALIDATION_FAILED: device_id required"}`, http.StatusBadRequest)
		return
	}
	st, _ := s.store2()
	if err := st.SetSubscriptionDeviceLimit(req.ID, req.DeviceID, req.Limit); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.device_limit", ObjectID: req.ID, Result: "ok", Detail: "device=" + req.DeviceID})
	writeJSON(w, http.StatusOK, map[string]any{"set": req.ID, "device": req.DeviceID})
}

// handleSubscriptionRotate re-issues the client fetch token (CAS on the
// current row, optional grace). The secret is shown ONCE in this response
// and never stored/logged.
func (s *server) handleSubscriptionRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID           string `json:"id"`
		GraceSeconds int    `json:"grace_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	endpoint, err := s.subscriptionEndpoint()
	if err != nil {
		writeErr(w, err)
		return
	}
	token, grace, err := svc.SubscriptionRotateToken(req.ID, time.Duration(req.GraceSeconds)*time.Second)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.rotate", ObjectID: req.ID, Result: "ok",
		Detail: "grace_seconds=" + fmtInt(grace)})
	if err := s.saveSubscriptionLink(req.ID, token); err != nil {
		log.Print("subscription link vault write failed")
	}
	writeIssuedSubscription(w, http.StatusOK, endpoint, token, map[string]any{"rotated": req.ID, "grace_seconds": grace})
}

// handleSubscriptionTransfer runs the ownership-transfer workflow (B43
// UI parity with the CLI: prepare → import → flip → activate is inside
// the service; the UI only collects the target).
func (s *server) handleSubscriptionTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID          string `json:"id"`
		TargetPanel string `json:"target_panel"`
		TargetBase  string `json:"target_base"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := svc.SubscriptionTransfer(req.ID, req.TargetPanel, req.TargetBase); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.transfer", ObjectID: req.ID, Result: "ok", Detail: "to=" + req.TargetPanel})
	writeJSON(w, http.StatusOK, map[string]any{"transferred": req.ID, "to": req.TargetPanel})
}

// handleSubscriptionQR renders the JUST-ISSUED subscription URL locally
// (core/qrencode; the token never travels to third-party services). The
// URL exists only in the create/rotate response — the endpoint does not
// recover stored tokens.
func (s *server) handleSubscriptionQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	raw, trojan := strings.CutSuffix(input.URL, "?format=links&protocol=trojan")
	if trojan && !localTrojanEnabled() {
		http.Error(w, "Unsupported ingress protocol", http.StatusBadRequest)
		return
	}
	raw, standard := strings.CutSuffix(raw, "?format=links")
	base, key, err := service.ParseSubscriptionLink(raw, "")
	e, eerr := s.subscriptionEndpoint()
	if err != nil || eerr != nil || e.Base() == "" || base != e.Base() {
		http.Error(w, `{"error":"VALIDATION_FAILED: invalid subscription URL"}`, http.StatusBadRequest)
		return
	}
	data := service.SubscriptionTokenURL(base, key)
	if trojan {
		data += "?format=links&protocol=trojan"
	} else if standard {
		data += "?format=links"
	}
	m, err := qrencode.Encode([]byte(data))
	if err != nil {
		writeErr(w, err)
		return
	}
	png, err := qrencode.PNG(m, 8)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"png": png})
}

func fmtInt(v int) string { return json.Number(intToString(v)).String() }

func intToString(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func localSubscriptionRUPort() int {
	port, _ := strconv.Atoi(os.Getenv("ARA_LOCAL_SUB_RU_PORT"))
	if port < 1 || port > 65535 {
		return 0
	}
	return port
}

func localTrojanEnabled() bool {
	return os.Getenv("ARA_LOCAL_SUB_EDGE") != "" && os.Getenv("ARA_LOCAL_TROJAN") == "1"
}

func (s *server) handleLocalSubscriptionProfiles(w http.ResponseWriter, r *http.Request) {
	edge := os.Getenv("ARA_LOCAL_SUB_EDGE")
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		sub, err := s.store.GetSubscription(id)
		if err != nil || sub.OwnerPanel != s.panelIdentity().PanelID {
			http.NotFound(w, r)
			return
		}
		profiles, err := s.store.ListSubscriptionProfiles(id)
		if err != nil {
			writeErr(w, err)
			return
		}
		nodes, err := s.store.ListNodes()
		if err != nil {
			writeErr(w, err)
			return
		}
		for i := range profiles {
			p := &profiles[i]
			p.SourcePanel = s.panelIdentity().PanelID
			for _, n := range nodes {
				if p.Kind == "transit" && n.IngressAddr == p.IngressAddr && n.IngressAddr != "" {
					p.EdgeNodeID = n.ID
				}
				if n.ID == p.NodeID && n.RemotePanel != "" {
					p.SourcePanel = n.RemotePanel
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles, "origin_panel": s.panelIdentity().PanelID})
	case http.MethodPost:
		var req struct {
			ID       string `json:"id"`
			Profiles []struct {
				Kind        string `json:"kind"`
				NodeID      string `json:"node_id"`
				EdgeNodeID  string `json:"edge_node_id"`
				ClientName  string `json:"name"`
				LimitBytes  *int64 `json:"limit_bytes"`
				DownloadBPS *int64 `json:"download_bps"`
				UploadBPS   *int64 `json:"upload_bps"`
			} `json:"profiles"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "VALIDATION_FAILED", 400)
			return
		}
		inputs := make([]service.SubscriptionInput, 0, len(req.Profiles))
		for _, p := range req.Profiles {
			inputs = append(inputs, service.SubscriptionInput{Kind: p.Kind, NodeID: p.NodeID, EdgeNodeID: p.EdgeNodeID, ClientName: p.ClientName, LimitBytes: p.LimitBytes, DownloadBPS: p.DownloadBPS, UploadBPS: p.UploadBPS})
		}
		if edge != "" {
			if err := s.verifyLocalServingRoutes(edge, inputs); err != nil {
				writeErr(w, err)
				return
			}
		}
		svc, err := s.service()
		if err == nil {
			if edge == "" {
				err = svc.SubscriptionSetProfiles(req.ID, inputs)
			} else {
				err = svc.SetLocalSubscriptionProfiles(req.ID, inputs, edge, localSubscriptionRUPort())
			}
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handlePanelShare exposes the same restricted operation as ara panel share.
func (s *server) handlePanelShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PanelID string   `json:"panel_id"`
		Base    string   `json:"base"`
		NodeIDs []string `json:"node_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil || req.PanelID == "" || len(req.NodeIDs) == 0 {
		http.Error(w, "VALIDATION_FAILED", http.StatusBadRequest)
		return
	}
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	result, err := svc.FederationShareSelectedTopology(req.PanelID, req.Base, req.NodeIDs)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "fed.topology.share", Result: "ok"})
	writeJSON(w, http.StatusOK, result)
}
