package main

import (
	"encoding/json"
	"net/http"
)

func (s *server) handleProfileBudget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body := readBody(w, r, 16<<10)
	if body == nil {
		return
	}
	peer, scopes, ok := s.verifyFed(w, r, body)
	if !ok {
		return
	}
	if !scopeHas(scopes, "quota") {
		http.Error(w, "PERMISSION_DENIED", 403)
		return
	}
	var req struct {
		SubID      string `json:"subscription_id"`
		ProfileKey string `json:"profile_key"`
		DeviceID   string `json:"device_id"`
		ID         string `json:"id"`
		Action     string `json:"action"`
		Bytes      int64  `json:"bytes"`
	}
	if json.Unmarshal(body, &req) != nil || !s.store.EdgeSubscriptionDelegated(peer, req.SubID) {
		http.Error(w, "PERMISSION_DENIED", 403)
		return
	}
	if req.Action == "close" {
		if err := s.store.ProfileClose(s.panelIdentity().PanelID, req.SubID, peer, req.ID, req.Bytes); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"closed": true})
		return
	}
	if req.Action != "reserve" {
		http.Error(w, "VALIDATION_FAILED", 400)
		return
	}
	grant, err := s.store.ProfileReserve(s.panelIdentity().PanelID, req.SubID, req.ProfileKey, peer, req.DeviceID, req.ID, req.Bytes)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, grant)
}
