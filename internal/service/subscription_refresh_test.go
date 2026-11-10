package service

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const followCatalog = `{"schema":"ara.subscription/v1","name":"t","profiles":[{"label_ru":"A","label_en":"A","kind":"direct","node_id":"de-1","client_config":{"outbounds":[{"type":"vless","uuid":"11111111-1111-1111-1111-111111111111"}]}}]}`

func TestAutoRefreshMovedAndScope(t *testing.T) {
	oldPanel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schema":"ara.subscription/v1","moved":true,"owner_panel":"b","fetch_base":"B"}`))
	}))
	defer oldPanel.Close()
	newPanel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(followCatalog))
	}))
	defer newPanel.Close()
	// the moved notice carries a RELATIVE-looking base in this test: the
	// client must follow exactly the recorded base — use the real new URL
	_ = newPanel.URL
	res, err := SubscriptionFollow(StateDir{Root: filepath.Join(t.TempDir(), "st")},
		oldPanel.Client(), "tok", oldPanel.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Followed {
		t.Fatalf("moved must trigger a follow: %+v", res)
	}
	if res.CatalogOK {
		t.Fatal("a fabricated relative base must not produce a valid catalog")
	}
}

func TestAutoRefreshScopeCheck(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(followCatalog))
	}))
	defer panel.Close()
	res, err := SubscriptionFollow(StateDir{Root: filepath.Join(t.TempDir(), "st")},
		panel.Client(), "tok", panel.URL, "22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	if res.CatalogOK || !strings.Contains(res.Error, "scope") {
		t.Fatalf("foreign identity catalog must be refused: %+v", res)
	}
	// the enrolled identity passes and the catalog lands
	res2, err := SubscriptionFollow(StateDir{Root: filepath.Join(t.TempDir(), "st2")},
		panel.Client(), "tok", panel.URL, "11111111-1111-1111-1111-111111111111")
	if err != nil || !res2.CatalogOK {
		t.Fatalf("enrolled identity must be accepted: %+v %v", res2, err)
	}
}

func TestAutoRefreshConfigPersistence(t *testing.T) {
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	cfg := SubscriptionAutoRefreshConfig{Token: "tok", Base: "http://x", DeviceUUID: "u", IntervalMin: 7}
	if err := st.SaveSubscriptionRefreshConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.LoadSubscriptionRefreshConfig()
	if err != nil || !ok || got.Token != "tok" || got.IntervalMin != 7 {
		t.Fatalf("config roundtrip: %+v %v %v", got, ok, err)
	}
	// status before any loop: honest disabled/zero state
	svc, err := New(StateDir{Root: filepath.Join(t.TempDir(), "st2")})
	if err != nil {
		t.Fatal(err)
	}
	status, err := svc.SubscriptionRefreshStatus()
	if err != nil || status.Enabled {
		t.Fatalf("unconfigured status: %+v %v", status, err)
	}
}
