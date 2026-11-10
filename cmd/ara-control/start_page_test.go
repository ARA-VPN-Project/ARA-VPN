package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartPagePersistsEscapesAndKeepsAdminPrivate(t *testing.T) {
	dir := t.TempDir()
	p := startPage{Mode: "custom", Title: "<script>alert(1)</script>", Text: "<img src=x onerror=alert(1)>\nHello"}
	if err := saveStartPage(dir, p); err != nil {
		t.Fatal(err)
	}
	got, err := readStartPage(dir)
	if err != nil || got != p {
		t.Fatalf("reopen: %v", err)
	}
	s := &server{stateDir: dir}
	w := httptest.NewRecorder()
	s.handleGuest(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<img ") {
		t.Fatal("unsafe page")
	}
	if !strings.Contains(w.Body.String(), "&lt;script&gt;") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing escaped content or CSP")
	}
	w = httptest.NewRecorder()
	s.handleGuest(w, httptest.NewRequest("GET", "/admin", nil))
	if w.Code != 404 {
		t.Fatal("public admin")
	}
	p.Mode = "unsupported"
	if saveStartPage(dir, p) == nil {
		t.Fatal("invalid mode accepted")
	}
	persisted, _ := readStartPage(dir)
	if persisted != got {
		t.Fatal("invalid update changed page")
	}
}
