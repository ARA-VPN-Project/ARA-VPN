package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aravpn/core/fedauth"
	"aravpn/internal/controlstore"
	"aravpn/internal/service"
)

func TestSubscriptionEndpointReplacesPublicPath(t *testing.T) {
	t.Setenv("ARA_SUB_CA", "system")
	dir := t.TempDir()
	st, err := controlstore.Open(filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ident, err := fedauth.LoadOrCreate(dir, "endpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	audit, err := controlstore.OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.StateDir{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{stateDir: dir, adminPath: "/operator", token: "fixture-operator-token", panelIdent: ident, svc: svc, store: st, audit: audit, mux: http.NewServeMux()}
	s.routes()
	panel := httptest.NewTLSServer(s.mux)
	defer panel.Close()
	request := func(method, path string, body any, admin bool, want int) []byte {
		t.Helper()
		var b io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			b = bytes.NewReader(data)
		}
		req, err := http.NewRequest(method, panel.URL+path, b)
		if err != nil {
			t.Fatal(err)
		}
		if admin {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := panel.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != want {
			t.Fatalf("response status %d, wanted %d: %v", res.StatusCode, want, err)
		}
		return data
	}
	settings := "/api/v1/subscriptions/endpoint"
	request("POST", settings, service.SubscriptionEndpoint{Origin: panel.URL, Name: "operator"}, true, 400)
	request("POST", settings, service.SubscriptionEndpoint{Origin: panel.URL, Name: "premium-vpn"}, false, 401)
	request("POST", settings, service.SubscriptionEndpoint{Origin: panel.URL, Name: "premium-vpn"}, true, 200)
	if _, err := st.CreateAccount("test", ""); err != nil {
		t.Fatal(err)
	}
	dev, _, err := st.CreateDevice("test", "phone")
	if err != nil {
		t.Fatal(err)
	}
	sub, token, err := st.CreateSubscriptionWithProfiles("test", "My VPN", ident.PanelID, nil, 0, nil, []controlstore.SubscriptionProfile{{Seq: 1, LabelRU: "Профиль", LabelEn: "Profile", Kind: "direct", NodeID: "egress", IngressAddr: "exit.example:443", SNI: "exit.example", Protocol: "vless"}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/premium-vpn/" + token
	catalog := request("GET", path, nil, false, 200)
	if !bytes.Contains(catalog, []byte(dev.VlessUUID)) || !bytes.Contains(catalog, []byte("My VPN")) {
		t.Fatal("wrong identity or subscription name")
	}
	if bytes.Contains(catalog, []byte("certificate_path")) {
		t.Fatal("system trust profile must use the client's trust store")
	}
	for _, app := range []string{"Shadowrocket/2", "Happ/3", "INCY/1", "Hiddify/4"} {
		req, err := http.NewRequest(http.MethodGet, panel.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", app)
		res, err := panel.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("%s HTTP %d: %v", app, res.StatusCode, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil || !strings.HasPrefix(string(decoded), "vless://"+dev.VlessUUID+"@exit.example:443?") {
			t.Fatalf("%s did not receive a VLESS subscription", app)
		}
	}
	request("GET", "/sub/"+token, nil, false, 404)
	request("GET", "/wrong/"+token, nil, false, 404)
	request("GET", "/premium-vpn/not-the-key", nil, false, 401)
	result := request("POST", "/api/v1/subscriptions/device-access", map[string]any{"id": sub.ID, "device_id": dev.ID, "action": "link"}, true, 200)
	var issued map[string]string
	if err := json.Unmarshal(result, &issued); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued["url"], panel.URL+"/premium-vpn/") {
		t.Fatal("device link did not use the configured endpoint")
	}
	qr := request("POST", "/api/v1/subscriptions/qr", map[string]string{"url": issued["url"]}, true, 200)
	var image map[string]string
	if err := json.Unmarshal(qr, &image); err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(base64.NewDecoder(base64.StdEncoding, strings.NewReader(image["png"]))); err != nil {
		t.Fatal("bad QR PNG")
	}
	base, key, err := service.ParseSubscriptionLink(issued["url"], "")
	if err != nil {
		t.Fatal(err)
	}
	follow, err := service.SubscriptionFollowChain(service.StateDir{Root: t.TempDir()}, panel.Client(), key, base, service.FollowOptions{EnrolledUUID: dev.VlessUUID, Deadline: 5 * time.Second})
	if err != nil || !follow.CatalogOK {
		t.Fatalf("custom URL import failed: %v %+v", err, follow)
	}
	request("POST", settings, service.SubscriptionEndpoint{Origin: panel.URL, Name: "new-service"}, true, 200)
	request("GET", path, nil, false, 404)
	request("GET", "/new-service/"+token, nil, false, 200)

	targetDir := t.TempDir()
	targetStore, err := controlstore.Open(filepath.Join(targetDir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer targetStore.Close()
	targetID, err := fedauth.LoadOrCreate(targetDir, "endpoint-target")
	if err != nil {
		t.Fatal(err)
	}
	targetSvc, err := service.New(service.StateDir{Root: targetDir})
	if err != nil {
		t.Fatal(err)
	}
	targetAudit, err := controlstore.OpenAudit(targetDir)
	if err != nil {
		t.Fatal(err)
	}
	target := &server{stateDir: targetDir, adminPath: "/target-admin", panelIdent: targetID, svc: targetSvc, store: targetStore, audit: targetAudit, mux: http.NewServeMux()}
	target.routes()
	destination := httptest.NewServer(target.mux)
	defer destination.Close()
	if _, err := targetSvc.SetSubscriptionEndpoint(service.SubscriptionEndpoint{Origin: destination.URL, Name: "target-connect"}, "/target-admin"); err != nil {
		t.Fatal(err)
	}
	if err := targetStore.AddLinkedPanel(ident.PanelID, ident.PublicHex(), "subscriptions"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SubscriptionTransfer(sub.ID, targetID.PanelID, destination.URL); err != nil {
		t.Fatal(err)
	}
	follow, err = service.SubscriptionFollowChain(service.StateDir{Root: t.TempDir()}, panel.Client(), token, panel.URL+"/new-service",
		service.FollowOptions{EnrolledUUID: dev.VlessUUID, AllowedBases: []string{destination.URL}, Deadline: 5 * time.Second})
	if err != nil || !follow.CatalogOK || !follow.Followed || follow.Base != destination.URL+"/target-connect" {
		t.Fatalf("transfer did not preserve the configured endpoint: %v %+v", err, follow)
	}

}
