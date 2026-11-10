package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"aravpn/internal/controlstore"
)

func (s *server) handleSubscriptionActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days != 1 && days != 7 {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: days must be 1 or 7"))
		return
	}
	id := r.URL.Query().Get("id")
	sub, err := s.store.GetSubscription(id)
	if err != nil || sub.OwnerPanel != s.panelIdentity().PanelID || sub.Active != nil && !*sub.Active {
		writeErr(w, fmt.Errorf("CONFLICT: subscription activity is available from its owner"))
		return
	}
	result, err := s.store.SubscriptionActivity(id, time.Now(), days)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleSubscriptionDeviceAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		SubscriptionID string `json:"id"`
		DeviceID       string `json:"device_id"`
		Action         string `json:"action"`
		Name           string `json:"name"`
		Expires        int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil ||
		input.SubscriptionID == "" || input.DeviceID == "" && input.Action != "add" {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: subscription and device are required"))
		return
	}
	owner := s.panelIdentity().PanelID
	var err error
	result := map[string]any{"device_id": input.DeviceID}
	switch input.Action {
	case "add":
		endpoint, eerr := s.subscriptionEndpoint()
		if eerr != nil {
			writeErr(w, eerr)
			return
		}
		dev, token, eerr := s.store.ProvisionSubscriptionDevice(input.SubscriptionID, owner, input.Name)
		if eerr != nil {
			writeErr(w, eerr)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.device.add", ObjectID: dev.ID, Result: "ok"})
		writeIssuedSubscription(w, http.StatusCreated, endpoint, token, map[string]any{"device_id": dev.ID, "device_name": dev.Name})
		return
	case "expiry":
		err = s.store.SetSubscriptionDeviceExpiry(input.SubscriptionID, owner, input.DeviceID, input.Expires)
	case "revoke":
		err = s.store.RevokeSubscriptionDevice(input.SubscriptionID, owner, input.DeviceID)
	case "link":
		endpoint, eerr := s.subscriptionEndpoint()
		if eerr != nil {
			writeErr(w, eerr)
			return
		}
		token, err := s.store.IssueSubscriptionDeviceLink(input.SubscriptionID, owner, input.DeviceID)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.device.link", ObjectID: input.DeviceID, Result: "ok"})
		writeIssuedSubscription(w, http.StatusOK, endpoint, token, result)
		return
	default:
		err = fmt.Errorf("VALIDATION_FAILED: unknown device action")
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.device." + input.Action, ObjectID: input.DeviceID, Result: "ok"})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}
