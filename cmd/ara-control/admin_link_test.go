package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aravpn/internal/controlstore"
)

func TestAdminLinkUsesSeparateKeysAndProtectsConsole(t *testing.T) {
	dir := t.TempDir()
	access, err := initializeAdminAccess(dir, "/my-control")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := initializeAdminAccess(dir, "/my-control")
	if err != nil || reopened != access || access.apiKey == access.linkKey {
		t.Fatalf("unexpected admin access initialization: stable=%t err=%v", reopened == access, err)
	}
	for _, name := range []string{"admin.path", "admin.link-key", "control.token"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private state %s: %v", name, err)
		}
	}
	if _, err := initializeAdminAccess(dir, "/sub"); err == nil {
		t.Fatal("reserved path accepted")
	}
	audit, err := controlstore.OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlstore.Open(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := &server{mux: http.NewServeMux(), token: access.apiKey, adminPath: access.webPath(), adminUsername: access.username, adminPassword: access.password, audit: audit, store: store}
	s.routes()

	request := func(method, path, body string, cookies []*http.Cookie, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://panel.example"+path, strings.NewReader(body))
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, r)
		return w
	}
	if status := request("GET", "/admin", "", nil, "").Code; status != 404 {
		t.Fatalf("default URL exposed: %d", status)
	}
	bootstrap := request("GET", access.webPath()+"?key="+access.linkKey, "", nil, "")
	if strings.Contains(bootstrap.Body.String(), "sec-overview") || len(bootstrap.Result().Cookies()) != 0 {
		t.Fatal("path/query rendered the console without a session")
	}
	for _, key := range []string{"wrong", access.apiKey} {
		if status := request("POST", access.webPath()+"/session", `{"key":"`+key+`"}`, nil, "").Code; status != 401 {
			t.Fatalf("wrong type of key accepted: %d", status)
		}
	}
	login := request("POST", access.webPath()+"/session", `{"username":"`+access.username+`","password":"`+access.password+`"}`, nil, "")
	cookies := login.Result().Cookies()
	if login.Code != 200 || len(cookies) != 2 || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatal("valid link did not create a protected session")
	}
	if body := request("GET", access.webPath(), "", cookies, "").Body.String(); !strings.Contains(body, "sec-overview") || strings.Contains(body, access.linkKey) {
		t.Fatal("console missing or contains link credential")
	}
	csrfAsSession := []*http.Cookie{{Name: cookieName, Value: cookies[1].Value}}
	if status := request("GET", "/api/v1/nodes", "", csrfAsSession, access.linkKey).Code; status != 401 {
		t.Fatalf("API accepted a link or CSRF key as authentication: %d", status)
	}
	if status := request("GET", "/api/v1/nodes", "", nil, access.apiKey).Code; status != 200 {
		t.Fatalf("API key stopped working: %d", status)
	}
	request("GET", access.webPath()+"/logout", "", cookies, "")
	if strings.Contains(request("GET", access.webPath(), "", cookies, "").Body.String(), "sec-overview") {
		t.Fatal("logged-out session still has access")
	}
}

func TestAdminLoginFiveAttemptsAndPasswordChange(t *testing.T) {
	s := &server{stateDir: t.TempDir(), adminUsername: "operator", adminPassword: "old password fixture"}
	req := httptest.NewRequest("POST", "https://example.invalid/login", nil)
	req.RemoteAddr = "127.0.0.1:9000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	now := time.Now()
	for i := 0; i < 5; i++ {
		if s.allowAdminLogin(req, "unknown", "wrong", now) {
			t.Fatal("invalid attempt accepted")
		}
	}
	if s.allowAdminLogin(req, "operator", "old password fixture", now.Add(9*time.Minute)) {
		t.Fatal("lockout bypass")
	}
	if !s.allowAdminLogin(req, "operator", "old password fixture", now.Add(10*time.Minute)) {
		t.Fatal("lockout failed to expire")
	}
	w := httptest.NewRecorder()
	s.handleChangeAdminPassword(w, httptest.NewRequest("POST", "https://example.invalid/password", strings.NewReader(`{"current":"old password fixture","new_password":"new password fixture"}`)))
	if w.Code != 200 {
		t.Fatalf("password change: %d", w.Code)
	}
	persisted, err := readChangedPassword(s.stateDir)
	if err != nil || persisted == "" {
		t.Fatal("password change not persisted")
	}
	reopened := &server{adminUsername: "operator", adminPassword: "old password fixture", login: adminLoginState{changed: persisted}}
	if reopened.allowAdminLogin(req, "operator", "old password fixture", now) || !reopened.allowAdminLogin(req, "operator", "new password fixture", now) {
		t.Fatal("wrong password after reopening")
	}
}
