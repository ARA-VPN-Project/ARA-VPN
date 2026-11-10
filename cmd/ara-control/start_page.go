package main

import (
	"aravpn/internal/controlstore"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type startPage struct {
	Mode  string `json:"mode"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

func readStartPage(dir string) (startPage, error) {
	p := startPage{Mode: "neutral", Title: "Welcome", Text: "A quiet place on the web."}
	b, err := os.ReadFile(filepath.Join(dir, "public-page.json"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, validateStartPage(p)
}
func validateStartPage(p startPage) error {
	if p.Mode != "neutral" && p.Mode != "custom" && p.Mode != "index" {
		return fmt.Errorf("VALIDATION_FAILED: invalid page mode")
	}
	if !utf8.ValidString(p.Title) || !utf8.ValidString(p.Text) || utf8.RuneCountInString(p.Title) > 120 || utf8.RuneCountInString(p.Text) > 6000 {
		return fmt.Errorf("VALIDATION_FAILED: page text is too long")
	}
	if p.Mode == "custom" && strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("VALIDATION_FAILED: title required")
	}
	return nil
}
func saveStartPage(dir string, p startPage) error {
	if err := validateStartPage(p); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".public-page-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "public-page.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *server) handleStartPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p, err := readStartPage(s.stateDir)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, p)
	case http.MethodPost:
		var p startPage
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			http.Error(w, "VALIDATION_FAILED", 400)
			return
		}
		if err := saveStartPage(s.stateDir, p); err != nil {
			writeErr(w, err)
			return
		}
		if s.audit != nil {
			s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "public-page.update", Result: "ok"})
		}
		writeJSON(w, 200, p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

var startPageTemplate = template.Must(template.New("public").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title>
<style>html{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;background:#f6f7f9;color:#22252b;font-family:system-ui,-apple-system,sans-serif}main{width:min(100%,760px);padding:clamp(32px,8vw,88px)}.mark{width:36px;height:4px;border-radius:4px;background:currentColor;opacity:.3;margin-bottom:32px}h1{font-size:clamp(30px,6vw,56px);font-weight:600;letter-spacing:-.035em;line-height:1.1;margin:0 0 24px;overflow-wrap:anywhere}p{font-size:clamp(16px,2.5vw,20px);line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere;opacity:.7;margin:0}@media(prefers-color-scheme:dark){body{background:#15171b;color:#eef0f4}}</style>
<main><div class="mark" aria-hidden="true"></div><h1>{{.Title}}</h1>{{if .Text}}<p>{{.Text}}</p>{{end}}</main></html>`))
