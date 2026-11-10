package main

// Transit profile management for the Control Center (RU/EN): the panel
// calls the SAME service layer as the CLI (docs/CLI_AUTOMATION.md — CLI
// equals UI). Protocol switching for an Edge→Exit link is the plan+apply
// pair; credentials arrive in the authenticated POST body, are stored in
// the protected secrets table and are never returned by any endpoint.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/internal/controlstore"
	"aravpn/internal/service"

	"strconv"
)

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, serviceCapabilities())
}

func (s *server) handleTransitProfiles(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, err := svc.OpenControlStore()
		if err != nil {
			writeErr(w, err)
			return
		}
		defer st.Close()
		profs, err := st.ListTransportProfiles(r.URL.Query().Get("node"))
		if err != nil {
			writeErr(w, err)
			return
		}
		// profiles never carry secret material — the list is the profile
		// rows themselves (credential_ref only)
		writeJSON(w, http.StatusOK, map[string]any{"profiles": profs, "capabilities": serviceCapabilities()})
	case http.MethodPost:
		var req struct {
			NodeID   string `json:"node_id"`
			Protocol string `json:"protocol"` // vless | trojan | hysteria2
			// ServerName/CAPath are the TLS parameters; Secret is the
			// protocol credential (trojan password etc.).
			ServerName string `json:"server_name"`
			CAPath     string `json:"ca_path"`
			Secret     string `json:"secret"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		if req.Secret == "" {
			http.Error(w, `{"error":"VALIDATION_FAILED: secret required"}`, http.StatusBadRequest)
			return
		}
		plan, hash, err := svc.TransitPlanAddProfile(transitProfileInput(req.NodeID, req.Protocol, req.ServerName, req.CAPath, req.Secret), time.Now().UTC())
		if err != nil {
			writeErr(w, err)
			return
		}
		if _, err := svc.TransitApply(plan.ID, hash); err != nil {
			writeErr(w, err)
			return
		}
		st, err := svc.OpenControlStore()
		if err != nil {
			writeErr(w, err)
			return
		}
		defer st.Close()
		profs, _ := st.ListTransportProfiles(req.NodeID)
		s.audit.Append(controlstore.AuditEntry{Actor: "panel", Action: "transit.profile.add", ObjectID: req.NodeID, Result: "ok",
			Detail: "protocol=" + req.Protocol})
		writeJSON(w, http.StatusCreated, map[string]any{"profiles": profs, "plan_id": plan.ID})
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleTransitProfileRevoke(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
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
	plan, hash, err := svc.TransitPlanRevokeProfile(req.ID, time.Now().UTC())
	if err != nil {
		writeErr(w, err)
		return
	}
	if _, err := svc.TransitApply(plan.ID, hash); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "panel", Action: "transit.profile.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

// handleLinkSetProtocol switches an Edge→Exit link's transport profile:
// the typed protocol change with plan/apply through the service layer.
func (s *server) handleLinkSetProtocol(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		LinkID    string `json:"link_id"`
		ProfileID string `json:"profile_id"`
		Legacy    bool   `json:"legacy"` // restore the legacy tcp VLESS+TLS default
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	target := req.ProfileID
	if req.Legacy {
		target = ""
	}
	plan, hash, err := svc.TransitPlanSetLinkProfile(req.LinkID, target, time.Now().UTC())
	if err != nil {
		writeErr(w, err)
		return
	}
	res, err := svc.TransitApply(plan.ID, hash)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "panel", Action: "link.set_profile", ObjectID: req.LinkID, Result: "ok",
		Detail: "profile=" + req.ProfileID})
	writeJSON(w, http.StatusOK, map[string]any{"applied": true, "plan_id": plan.ID, "result": res})
}

func transitProfileInput(nodeID, protocol, sni, ca, secret string) (in service.TransitProfileInput) {
	in = service.TransitProfileInput{NodeID: nodeID, Protocol: protocol, Security: "tls", Secret: secret}
	in.TLS.ServerName = sni
	in.TLS.CAPath = ca
	return in
}

func serviceCapabilities() map[string]any {
	return service.TransitCapabilities()
}

// handleDiagHistory serves the LOCAL edge speedtest history for the graphs
// (metrics only, no secrets). When the edge runs on another host, the
// operator imports the JSONL file; the endpoint reports which source is live.
// handleMonitoringHistory serves the bounded availability/RTT ring (G-wave).
func (s *server) handleMonitoringHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.mon == nil {
		http.Error(w, `{"error":"MONITORING_UNAVAILABLE"}`, http.StatusServiceUnavailable)
		return
	}
	if period := r.URL.Query().Get("period"); period != "" && period != "1h" {
		var span, step time.Duration
		switch period {
		case "24h":
			span, step = 24*time.Hour, 5*time.Minute
		case "7d":
			span, step = 7*24*time.Hour, time.Hour
		case "30d":
			span, step = 30*24*time.Hour, 4*time.Hour
		case "1y":
			span, step = 365*24*time.Hour, 24*time.Hour
		default:
			writeErr(w, fmt.Errorf("VALIDATION_FAILED: unknown monitoring period"))
			return
		}
		samples, err := s.mon.Period(time.Now(), span, step)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"samples": samples, "interval_seconds": int(step.Seconds())})
		return
	}
	n := 200
	if sn := r.URL.Query().Get("n"); sn != "" {
		if v, err := strconv.Atoi(sn); err == nil && v > 0 && v <= 2000 {
			n = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": s.mon.History(n), "edge_enabled": s.monitorEdge, "cloudflare_enabled": s.monitorCloudflare, "interval_seconds": int(monitorInterval.Seconds())})
}

func (s *server) handleDiagHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	stDir := s.stateDir
	if stDir == "" {
		var err error
		stDir, err = resolveDir(os.Getenv("ARA_STATE_DIR"))
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	path := filepath.Join(stDir, "speedtest-history.jsonl")
	data, rerr := os.ReadFile(path)
	source := "edge-local"
	if rerr != nil {
		// fallback: client-side speedtest job history from the shared service state
		source = "none"
		writeJSON(w, http.StatusOK, map[string]any{"source": source, "records": []any{}})
		return
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			recs = append(recs, m)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": source, "records": recs})
}
