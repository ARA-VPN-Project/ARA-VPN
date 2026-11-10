package main

import (
	"aravpn/internal/controlstore"
	"aravpn/internal/service"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (s *server) handleEdgeDeploymentPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in service.EdgeConfigInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: invalid Edge deployment request"))
		return
	}
	if dec.Decode(new(any)) != io.EOF {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: one JSON object required"))
		return
	}
	p, hash, _, err := s.svc.EdgeConfigPlan(in, time.Now().UTC())
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"plan_id": p.ID, "plan_hash": hash, "expires_at": p.ExpiresAt, "edge_panel_id": in.EdgePanelID, "edge_node_id": in.EdgeNodeID, "plan": p})
}
func (s *server) handleEdgeDeploymentApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		PlanID string `json:"plan_id"`
		Hash   string `json:"plan_hash"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || in.PlanID == "" || in.Hash == "" || dec.Decode(new(any)) != io.EOF {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: plan_id and plan_hash required"))
		return
	}
	result, err := s.svc.EdgeConfigApply(in.PlanID, in.Hash)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "edgeconfig.apply", ObjectID: in.PlanID, Result: "ok"})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"result": result, "state": "dispatched", "serving_confirmed": false})
}
