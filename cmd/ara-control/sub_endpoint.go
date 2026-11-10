package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"aravpn/internal/controlstore"
	"aravpn/internal/service"
)

func (s *server) subscriptionEndpoint() (service.SubscriptionEndpoint, error) {
	svc, err := s.service()
	if err != nil {
		return service.SubscriptionEndpoint{}, err
	}
	e, err := svc.SubscriptionEndpoint()
	if err != nil {
		return e, err
	}
	if err := service.ValidateSubscriptionServiceName(e.Name, s.adminPath); err != nil {
		return e, err
	}
	if e.Origin == "" {
		origin := os.Getenv("ARA_PUBLIC_URL")
		if origin == "" {
			if b, e := os.ReadFile(filepath.Join(s.stateDir, "admin.origin")); e == nil {
				origin = strings.TrimSpace(string(b))
			} else if !os.IsNotExist(e) {
				return service.SubscriptionEndpoint{}, e
			}
		}
		if origin != "" {
			e.Origin, err = service.LinkOrigin(origin)
		}
	}
	return e, err
}

func (s *server) handleSubscriptionEndpoint(w http.ResponseWriter, r *http.Request) {
	var e service.SubscriptionEndpoint
	var err error
	switch r.Method {
	case http.MethodGet:
		e, err = s.subscriptionEndpoint()
	case http.MethodPost:
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&e); err != nil {
			writeErr(w, fmt.Errorf("VALIDATION_FAILED: invalid subscription endpoint"))
			return
		}
		svc, openErr := s.service()
		if openErr != nil {
			writeErr(w, openErr)
			return
		}
		e, err = svc.SetSubscriptionEndpoint(e, s.adminPath)
		if err == nil {
			s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "subscription.endpoint", ObjectID: e.Name, Result: "ok"})
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func writeIssuedSubscription(w http.ResponseWriter, status int, e service.SubscriptionEndpoint, token string, fields map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	fields["token"] = token
	if e.Base() != "" {
		fields["url"] = service.SubscriptionTokenURL(e.Base(), token)
	}
	writeJSON(w, status, fields)
}

// Initialize the fresh-install subscription endpoint from the installer's
// validated origin. Keep the legacy default when subscriptions already exist.
func (s *server) initializeSubscriptionEndpoint() error {
	if _, err := os.Stat(filepath.Join(s.stateDir, "subscription-endpoint.json")); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	endpoint, err := s.subscriptionEndpoint()
	if err != nil {
		return err
	}
	if endpoint.Origin == "" {
		return nil
	}
	subs, err := s.store.ListSubscriptions()
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		endpoint.Name = "connect"
	}
	_, err = s.svc.SetSubscriptionEndpoint(endpoint, s.adminPath)
	return err
}
