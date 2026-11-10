package main

import (
	"aravpn/core/fedauth"
	"aravpn/internal/controlstore"
	"aravpn/internal/service"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestFreshPanelCanEditOwnedSubscriptionProfiles(t *testing.T) {
	t.Setenv("ARA_LOCAL_SUB_EDGE", "")
	dir := t.TempDir()
	ident, err := fedauth.LoadOrCreate(dir, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.StateDir{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	st, err := controlstore.Open(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.CreateAccount("a", "")
	st.AddNodeFull("se", "SE", "foreign", 1, "example.invalid:443", "example.invalid")
	sub, _, err := svc.SubscriptionCreate("a", "test", nil, 0, []service.SubscriptionInput{{Kind: "direct", NodeID: "se"}})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{store: st, svc: svc, stateDir: dir, panelIdent: ident}
	w := httptest.NewRecorder()
	s.handleLocalSubscriptionProfiles(w, httptest.NewRequest("GET", "/api/v1/subscriptions/profiles?id="+sub.ID, nil))
	if w.Code != 200 {
		t.Fatalf("fresh GET: %d %s", w.Code, w.Body.String())
	}
	b, _ := json.Marshal(map[string]any{"id": sub.ID, "profiles": []any{map[string]any{"kind": "direct", "node_id": "se", "name": "My Sweden", "download_bps": 1000000, "limit_bytes": 100000}}})
	w = httptest.NewRecorder()
	s.handleLocalSubscriptionProfiles(w, httptest.NewRequest("POST", "/api/v1/subscriptions/profiles", bytes.NewReader(b)))
	if w.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	ps, err := st.ListSubscriptionProfiles(sub.ID)
	if err != nil || len(ps) != 1 || ps[0].LabelRU != "My Sweden" || ps[0].DownloadBPS == nil || *ps[0].DownloadBPS != 1000000 || ps[0].LimitBytes == nil || *ps[0].LimitBytes != 100000 {
		t.Fatalf("not persisted: %+v %v", ps, err)
	}
	foreign, _, err := st.CreateSubscriptionWithProfiles("a", "foreign", "other", nil, 0, nil, ps)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SubscriptionSetProfiles(foreign.ID, []service.SubscriptionInput{{Kind: "direct", NodeID: "se"}})
	if err == nil {
		t.Fatal("foreign owner was modified")
	}
}
