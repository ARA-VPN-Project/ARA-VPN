package service

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const chainCatalog = `{"schema":"ara.subscription/v1","name":"t","profiles":[{"label_ru":"A","label_en":"A","kind":"direct","node_id":"de-1","client_config":{"outbounds":[{"type":"vless","uuid":"11111111-1111-1111-1111-111111111111","server":"10.62.0.2","server_port":8443,"tls":{"enabled":true,"server_name":"edge.ara.lab","certificate_path":"/tmp/ca.crt"}}]}}]}`

func chainPanel(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
}

// A→B→C with the SAME token: the chain follows two moved notices and
// lands on the final owner's catalog.
func TestChainFollowABC(t *testing.T) {
	cURL := ""
	cPanel := chainPanel(t, chainCatalog)
	defer cPanel.Close()
	cURL = cPanel.URL
	bPanel := chainPanel(t, `{"schema":"ara.subscription/v1","moved":true,"fetch_base":"`+cURL+`"}`)
	defer bPanel.Close()
	aPanel := chainPanel(t, `{"schema":"ara.subscription/v1","moved":true,"fetch_base":"`+bPanel.URL+`"}`)
	defer aPanel.Close()
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	res, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", aPanel.URL,
		FollowOptions{EnrolledUUID: "11111111-1111-1111-1111-111111111111", AllowedBases: []string{bPanel.URL, cPanel.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Followed || !res.CatalogOK || res.Base != cURL {
		t.Fatalf("chain: %+v err=%v", res, err)
	}
}

// cycle A→B→A terminates with a typed chain error.
func TestChainCycleTerminates(t *testing.T) {
	var aURL, bURL string
	var mu sync.Mutex
	respond := func(next string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Write([]byte(`{"schema":"ara.subscription/v1","moved":true,"fetch_base":"` + next + `"}`))
		}
	}
	var aSrv, bSrv *httptest.Server
	aSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		next := bURL
		mu.Unlock()
		respond(next)(w, r)
	}))
	defer aSrv.Close()
	bSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		next := aURL
		mu.Unlock()
		respond(next)(w, r)
	}))
	defer bSrv.Close()
	mu.Lock()
	aURL, bURL = aSrv.URL, bSrv.URL
	mu.Unlock()
	aURL, bURL = aSrv.URL, bSrv.URL
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	_, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", aURL,
		FollowOptions{AllowedBases: []string{aURL, bURL}})
	if err == nil || !strings.Contains(err.Error(), "FOLLOW_CHAIN") {
		t.Fatalf("cycle must terminate typed: %v", err)
	}
}

// hop limit and deadline bound the chain.
func TestChainHopLimit(t *testing.T) {
	var srvURL string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu2.Lock()
		u := srvURL
		mu2.Unlock()
		w.Write([]byte(`{"schema":"ara.subscription/v1","moved":true,"fetch_base":"` + u + `"}`))
	}))
	defer srv.Close()
	mu2.Lock()
	srvURL = srv.URL
	mu2.Unlock()
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	_, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", srv.URL,
		FollowOptions{MaxHops: 2, AllowedBases: []string{srv.URL}})
	if err == nil || !strings.Contains(err.Error(), "FOLLOW_CHAIN") {
		t.Fatalf("hop limit must terminate typed: %v", err)
	}
}

var mu2 sync.Mutex

// HTTP redirects are refused outright — the token never follows them.
func TestChainRefusesHTTPRedirect(t *testing.T) {
	var target string
	target = ""
	target2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"schema":"ara.subscription/v1","profiles":[]}`))
	}))
	defer target2.Close()
	_ = target
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target2.URL, http.StatusFound)
	}))
	defer srv.Close()
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	res, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", srv.URL, FollowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Error, "ORIGIN_POLICY") {
		t.Fatalf("redirect must be refused with origin policy: %+v", res)
	}
}

// https→http downgrade is refused.
func TestChainRefusesDowngrade(t *testing.T) {
	// the test cannot serve https easily; simulate by an explicitly http
	// source whose next hop is a NON-listed http base → refusal via the
	// allow-list rule
	srv := chainPanel(t, `{"schema":"ara.subscription/v1","moved":true,"fetch_base":"http://127.0.0.1:1"}`)
	defer srv.Close()
	st := StateDir{Root: filepath.Join(t.TempDir(), "st")}
	res, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", srv.URL, FollowOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Error, "ORIGIN_POLICY") {
		t.Fatalf("non-listed http base must be refused: %+v", res)
	}
}

// the applied profile: catalog profile lands in profiles/default.json with
// local engine/TUN preserved; a broken catalog keeps the previous profile.
func TestChainAppliesProfile(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "profiles")
	st := StateDir{Root: dir}
	panel := chainPanel(t, chainCatalog)
	defer panel.Close()
	res, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", panel.URL,
		FollowOptions{EnrolledUUID: "11111111-1111-1111-1111-111111111111",
			ApplyProfile: true, ProfileDir: pdir,
			ExistingProf: &osProfile{EnginePath: "/usr/bin/sing-box", TUNName: "ara-tun",
				TUNAddr4: "10.99.0.1/30", MTU: 1400}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ProfileApplied {
		t.Fatalf("profile not applied: %+v", res)
	}
	b, err := readProfile(pdir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "10.62.0.2:8443") || !strings.Contains(string(b), "/usr/bin/sing-box") {
		t.Fatalf("profile must merge catalog endpoint with local engine: %s", b)
	}
	// broken catalog: apply fails, previous profile stays
	broken := chainPanel(t, `{"schema":"ara.subscription/v1","profiles":[{"client_config":{"outbounds":[{"server":"x"}]}}]}`)
	defer broken.Close()
	res2, err := SubscriptionFollowChain(st, FollowHTTPClient(20*time.Second), "tok", broken.URL,
		FollowOptions{EnrolledUUID: "11111111-1111-1111-1111-111111111111",
			ApplyProfile: true, ProfileDir: pdir})
	if err != nil {
		t.Fatal(err)
	}
	if res2.ProfileApplied || res2.CatalogOK {
		t.Fatalf("broken catalog must not apply: %+v", res2)
	}
	b2, err := readProfile(pdir)
	if err != nil || !strings.Contains(string(b2), "10.62.0.2:8443") {
		t.Fatalf("previous profile must survive: %v %s", err, b2)
	}
}

func readProfile(dir string) ([]byte, error) {
	return osReadFile(filepath.Join(dir, "default.json"))
}

func TestChainFollowsDifferentSubscriptionService(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/new-brand/fixture-key" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(chainCatalog))
	}))
	defer final.Close()
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/old-brand/fixture-key" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"schema":"ara.subscription/v1","moved":true,"fetch_base":"` + final.URL + `/new-brand"}`))
	}))
	defer initial.Close()
	result, err := SubscriptionFollowChain(StateDir{Root: t.TempDir()}, FollowHTTPClient(5*time.Second), "fixture-key", initial.URL+"/old-brand", FollowOptions{AllowedBases: []string{final.URL}})
	if err != nil || !result.CatalogOK || !result.Followed || result.Base != final.URL+"/new-brand" {
		t.Fatalf("custom moved endpoint failed: %v %+v", err, result)
	}
}
