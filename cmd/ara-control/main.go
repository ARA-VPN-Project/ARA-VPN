// Command ara-control is the control plane service: a loopback-bound REST
// API over the local registry (devices, nodes, audit). Management is bound
// to 127.0.0.1 by default. An explicit certificate and key enable HTTPS.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"aravpn/core/fedauth"
	"aravpn/core/nodeaccess"
	"aravpn/core/policy"
	"aravpn/internal/controlstore"
	"aravpn/internal/monitoring"
	"aravpn/internal/service"
	"aravpn/internal/tlswizard"
)

type server struct {
	nodeCheck         sync.Mutex
	stateDir          string
	store             *controlstore.Store
	audit             *controlstore.Audit
	token             string // operator token from state dir
	adminPath         string
	adminUsername     string
	adminPassword     string
	login             adminLoginState
	mux               *http.ServeMux
	svc               *service.Service
	panelIdent        *fedauth.Identity // this panel's federation key
	mon               *monitoring.Store
	monitorEdge       bool
	httpsEnabled      bool
	edgeStatusPath    string
	monitorCloudflare bool
	nodeAccessSocket  string
}

// service returns the shared typed service layer over the control state
// dir (policy/limits run the same plan discipline as the CLI).
func (s *server) service() (*service.Service, error) {
	if s.svc != nil {
		return s.svc, nil
	}
	st, err := resolveDir(os.Getenv("ARA_STATE_DIR"))
	if err != nil {
		return nil, err
	}
	svc, err := service.New(service.StateDir{Root: st})
	if err != nil {
		return nil, err
	}
	s.svc = svc
	return svc, nil
}

func main() {
	stateDir := flag.String("state-dir", os.Getenv("ARA_STATE_DIR"), "state directory")
	listen := flag.String("listen", "127.0.0.1:8080", "management listen address (loopback by default)")
	tlsCert := flag.String("tls-cert", os.Getenv("ARA_HTTPS_CERT"), "HTTPS certificate chain PEM")
	tlsKey := flag.String("tls-key", os.Getenv("ARA_HTTPS_KEY"), "HTTPS private key PEM")
	allowNonLoopback := flag.Bool("allow-non-loopback", false, "explicitly allow a non-loopback listen (container deployments where the runtime publishes the port on the host loopback; never combine with unrestricted host publishing)")
	edgeStatus := flag.String("monitor-edge-status", os.Getenv("ARA_MONITOR_EDGE_STATUS"), "local trusted ara-edge status JSON")
	accessSocket := flag.String("node-access-socket", os.Getenv("ARA_NODE_ACCESS_SOCKET"), "local Unix socket for scoped nftables management")
	cloudflare := flag.Bool("monitor-cloudflare", os.Getenv("ARA_MONITOR_CLOUDFLARE") == "1", "enable TCP checks to Cloudflare, Facebook and Yandex from this panel")
	adminPath := flag.String("admin-path", os.Getenv("ARA_ADMIN_PATH"), "custom administrative link path")
	panelID := flag.String("panel-id", os.Getenv("ARA_PANEL_ID"), "panel identity to initialize on a new installation")
	initOnly := flag.Bool("init-admin", false, "initialize administrative access files and exit")
	showLink := flag.Bool("admin-link", false, "print the private relative administrative link and exit")
	adminOrigin := flag.String("admin-origin", os.Getenv("ARA_ADMIN_ORIGIN"), "public HTTPS origin for administrative links")
	showCredentials := flag.Bool("admin-credentials", false, "print the private admin address, username and password")
	publicPageFile := flag.String("set-public-page", "", "save public page settings from a JSON file and exit")
	flag.Parse()
	if *showCredentials {
		*showLink = true
	}
	if *initOnly && *showLink {
		log.Fatal("--init-admin and --admin-link are mutually exclusive")
	}
	serveTLS := *tlsCert != "" && *tlsKey != ""
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("--tls-cert and --tls-key must be configured together")
	}
	if !*initOnly && !*showLink && !isLoopbackListen(*listen) && !*allowNonLoopback && !serveTLS {
		log.Fatalf("refusing to listen on %s: management binds loopback only; pass --allow-non-loopback for container deployments where the port is published on the host loopback, or use an authenticated TLS proxy for remote access", *listen)
	}
	if !*initOnly && !*showLink && !isLoopbackListen(*listen) && *allowNonLoopback && !serveTLS {
		log.Printf("WARNING: management listening on %s with an explicit non-loopback override; the operator is responsible for restricting exposure (host loopback publish, TLS proxy, network policy)", *listen)
	}
	st, err := resolveDir(*stateDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(st, 0o700); err != nil {
		log.Fatal(err)
	}
	if *publicPageFile != "" {
		b, err := os.ReadFile(*publicPageFile)
		if err != nil {
			log.Fatal(err)
		}
		var p startPage
		if err = json.Unmarshal(b, &p); err != nil {
			log.Fatal(err)
		}
		if err = saveStartPage(st, p); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Public page saved")
		return
	}
	access, err := initializeAdminAccess(st, *adminPath)
	if err != nil {
		log.Fatalf("admin access: %v", err)
	}
	changedPassword, err := readChangedPassword(st)
	if err != nil {
		log.Fatal(err)
	}
	if *initOnly {
		return
	}
	if *showLink {
		if !*showCredentials {
			fmt.Println(access.webPath())
			return
		}
		origin, err := configuredAdminOrigin(st, *adminOrigin)
		if err != nil {
			log.Fatal(err)
		}
		password := access.password
		if changedPassword != "" {
			password = "(changed in Settings)"
		}
		if origin != "" {
			fmt.Printf("URL: %s%s\n", origin, access.webPath())
		} else {
			fmt.Printf("Path: %s\n", access.webPath())
			fmt.Println("Public HTTPS origin is not configured. Append the path to the server HTTPS address, or pass --admin-origin https://your-domain.")
			fmt.Println("Публичный HTTPS-адрес ещё не задан. Добавьте путь к адресу сервера или укажите --admin-origin https://ваш-домен.")
		}
		fmt.Printf("Username: %s\nPassword: %s\n", access.username, password)
		return
	}
	store, err := controlstore.Open(filepath.Join(st, "control.db"))
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
	audit, err := controlstore.OpenAudit(st)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}

	panelIdent, err := fedauth.LoadOrCreate(st, *panelID)
	if err != nil {
		log.Fatalf("panel identity: %v (on first start set --panel-id or ARA_PANEL_ID)", err)
	}
	log.Printf("panel id: %s", panelIdent.PanelID)
	mon, err := monitoring.OpenStore(st, 2000)
	if err != nil {
		log.Printf("monitoring history unavailable: %v", err)
	} else if err := mon.OpenArchive(st); err != nil {
		log.Printf("monitoring archive unavailable: %v", err)
	}
	svc, err := service.New(service.StateDir{Root: st})
	if err != nil {
		log.Fatal(err)
	}
	s := &server{stateDir: st, store: store, audit: audit, svc: svc, token: access.apiKey, adminPath: access.webPath(), adminUsername: access.username, adminPassword: access.password, login: adminLoginState{changed: changedPassword}, mux: http.NewServeMux(), panelIdent: panelIdent, mon: mon, monitorEdge: *edgeStatus != "", monitorCloudflare: *cloudflare, nodeAccessSocket: *accessSocket, httpsEnabled: serveTLS}
	if err := s.initializeSubscriptionEndpoint(); err != nil {
		log.Fatalf("subscription endpoint: %v", err)
	}
	s.edgeStatusPath = *edgeStatus
	s.routes()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.routeListBackground(ctx)
	if mon != nil && (s.monitorEdge || s.monitorCloudflare) {
		go collectMonitoring(ctx, mon, *edgeStatus, *cloudflare)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Printf("ara-control listening on %s (TLS: %t)", *listen, serveTLS)
	if serveTLS {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func (s *server) routes() {
	// one origin: guest site, enrollment landing, admin panel
	s.mux.HandleFunc("/", s.handleGuest)
	if os.Getenv("ARA_HIDE_PUBLIC_ENROLL") != "1" {
		s.mux.HandleFunc("/enroll", s.handleEnrollPage)
	}
	s.mux.HandleFunc("POST "+s.adminPath+"/password", s.auth(s.handleChangeAdminPassword))
	s.mux.HandleFunc("/api/v1/subscriptions/link", s.auth(s.handleSavedSubscriptionLink))
	s.mux.HandleFunc("GET "+s.adminPath, s.handleAdminPage)
	s.mux.HandleFunc("POST "+s.adminPath+"/session", s.handleLogin)
	s.mux.HandleFunc("GET "+s.adminPath+"/logout", s.handleLogout)
	s.mux.HandleFunc("/api/v1/links", s.auth(s.handleLinks))
	s.mux.HandleFunc("/api/v1/links/revoke", s.auth(s.handleLinkRevoke))
	s.mux.HandleFunc("/api/v1/policy", s.auth(s.handlePolicy))
	s.mux.HandleFunc("/api/v1/policy/lists", s.auth(s.handleRouteLists))
	s.mux.HandleFunc("/api/v1/policy/lists/refresh", s.auth(s.handleRouteLists))
	s.mux.HandleFunc("/api/v1/policy/presets", s.auth(s.handleRoutePresets))
	s.mux.HandleFunc("/api/v1/policy/draft/validate", s.auth(s.handlePolicyDraftValidate))
	s.mux.HandleFunc("/api/v1/policy/preview", s.auth(s.handlePolicyPreview))
	s.mux.HandleFunc("/api/v1/policy/pool", s.auth(s.handlePolicyPool))
	s.mux.HandleFunc("/api/v1/policy/diff-plan", s.auth(s.handlePolicyDiffPlan))
	s.mux.HandleFunc("/api/v1/policy/apply", s.auth(s.handlePolicyApplyApply))
	s.mux.HandleFunc("/api/v1/limits", s.auth(s.handleLimits))
	s.mux.HandleFunc("/api/v1/tls", s.auth(s.handleTLSStatus))
	s.mux.HandleFunc("/api/v1/ping", s.auth(s.handlePing))
	s.mux.HandleFunc("/api/v1/edge-config", s.auth(s.handleEdgeConfig))
	s.mux.HandleFunc("/api/v1/edge-config/plan", s.auth(s.handleEdgeDeploymentPlan))
	s.mux.HandleFunc("/api/v1/edge-config/apply", s.auth(s.handleEdgeDeploymentApply))
	s.mux.HandleFunc("/api/v1/accounts", s.auth(s.handleAccounts))
	s.mux.HandleFunc("/api/v1/accounts/delete", s.auth(s.handleAccountDelete))
	s.mux.HandleFunc("/api/v1/devices", s.auth(s.handleDevices))
	s.mux.HandleFunc("/api/v1/devices/revoke", s.auth(s.handleDeviceRevoke))
	s.mux.HandleFunc("/api/v1/nodes", s.auth(s.handleNodes))
	s.mux.HandleFunc("/api/v1/nodes/check", s.auth(s.handleNodeCheck))
	s.mux.HandleFunc("/api/v1/nodes/access/plan", s.auth(s.handleNodeAccessPlan))
	s.mux.HandleFunc("/api/v1/nodes/access/apply", s.auth(s.handleNodeAccessChange))
	s.mux.HandleFunc("/api/v1/nodes/access/remove", s.auth(s.handleNodeAccessChange))
	s.mux.HandleFunc("/api/v1/nodes/ingress", s.auth(s.handleNodeIngress))
	s.mux.HandleFunc("/api/v1/nodes/revoke", s.auth(s.handleNodeRevoke))
	s.mux.HandleFunc("/api/v1/audit", s.auth(s.handleAudit))
	s.mux.HandleFunc("/api/v1/capabilities", s.auth(s.handleCapabilities))
	s.mux.HandleFunc("/api/v1/transit-profiles", s.auth(s.handleTransitProfiles))
	s.mux.HandleFunc("/api/v1/transit-profiles/revoke", s.auth(s.handleTransitProfileRevoke))
	s.mux.HandleFunc("/api/v1/links/set-profile", s.auth(s.handleLinkSetProtocol))
	s.mux.HandleFunc("/api/v1/invites", s.auth(s.handleInvites))
	s.mux.HandleFunc("/api/v1/invites/revoke", s.auth(s.handleInviteRevoke))
	// public redeem: rate-limited, single-use; the token travels in the
	// POST body (the enrollment link carries it in the URL fragment, which
	// never reaches server logs or referrers)
	s.mux.HandleFunc("/api/v1/invites/redeem", s.handleInviteRedeem)
	// federation (signed, limited scopes) and the public subscription fetch
	s.mux.HandleFunc("/api/fed/v1/link/redeem", s.handleFedLinkRedeem)
	s.mux.HandleFunc("/api/fed/v1/topology/import", s.handleFedTopologyImport)
	s.mux.HandleFunc("/api/fed/v1/subscription/import", s.handleFedSubImport)
	s.mux.HandleFunc("/api/fed/v1/subscription/activate", s.handleFedSubActivate)
	s.mux.HandleFunc("/api/fed/v1/edge/config", s.handleFedEdgeConfig)
	s.mux.HandleFunc("/api/fed/v1/quota/report", s.handleFedQuotaReport)
	s.mux.HandleFunc("/api/fed/v1/quota/profile", s.handleProfileBudget)
	s.mux.HandleFunc("/api/fed/v1/link/revoke", s.handleFedLinkRevoke)
	s.mux.HandleFunc("GET /{subscription_service}/{subscription_token}", s.handleSubFetch)
	s.mux.HandleFunc("/api/v1/public-page", s.auth(s.handleStartPage))
	s.mux.HandleFunc("/api/v1/subscriptions/endpoint", s.auth(s.handleSubscriptionEndpoint))
	s.mux.HandleFunc("/api/v1/panel/invites", s.auth(s.handlePanelInvites))
	s.mux.HandleFunc("/api/v1/panel/links", s.auth(s.handlePanelLinks))
	s.mux.HandleFunc("/api/v1/panel/redeem", s.auth(s.handlePanelRedeem))
	s.mux.HandleFunc("/api/v1/panel/share", s.auth(s.handlePanelShare))
	s.mux.HandleFunc("/api/v1/subscriptions", s.auth(s.handleSubscriptions))
	s.mux.HandleFunc("/api/v1/subscriptions/profiles", s.auth(s.handleLocalSubscriptionProfiles))
	s.mux.HandleFunc("/api/v1/subscriptions/activity", s.auth(s.handleSubscriptionActivity))
	s.mux.HandleFunc("/api/v1/subscriptions/device-access", s.auth(s.handleSubscriptionDeviceAccess))
	s.mux.HandleFunc("/api/v1/subscriptions/revoke", s.auth(s.handleSubscriptionRevoke))
	s.mux.HandleFunc("/api/v1/subscriptions/delete", s.auth(s.handleSubscriptionDelete))
	s.mux.HandleFunc("/api/v1/subscriptions/quota", s.auth(s.handleSubscriptionQuota))
	s.mux.HandleFunc("/api/v1/subscriptions/rotate", s.auth(s.handleSubscriptionRotate))
	s.mux.HandleFunc("/api/v1/diagnostics/history", s.auth(s.handleDiagHistory))
	s.mux.HandleFunc("/api/v1/monitoring/history", s.auth(s.handleMonitoringHistory))
	s.mux.HandleFunc("/api/v1/subscriptions/rate", s.auth(s.handleSubscriptionRate))
	s.mux.HandleFunc("/api/v1/subscriptions/device-limit", s.auth(s.handleSubscriptionDeviceLimit))
	s.mux.HandleFunc("/api/v1/subscriptions/device-slots", s.auth(s.handleSubscriptionDeviceSlots))
	s.mux.HandleFunc("/api/v1/subscriptions/transfer", s.auth(s.handleSubscriptionTransfer))
	s.mux.HandleFunc("/api/v1/subscriptions/qr", s.auth(s.handleSubscriptionQR))
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

// auth enforces the bearer token and logs the action to the audit trail.
// CORS is never a substitute for auth: no CORS headers are emitted at all.
func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if s.token != "" && strings.HasPrefix(h, "Bearer ") && subtleCompare(strings.TrimPrefix(h, "Bearer "), s.token) == 1 {
			next(w, r)
			return
		}
		if s.isAdmin(r) {
			if r.Method == http.MethodGet {
				next(w, r)
				return
			}
			csrfCookie, err := r.Cookie("ara_csrf")
			if err == nil && csrfCookie.Value != "" && r.Header.Get("X-CSRF") == csrfCookie.Value && validSessionCSRF(r, csrfCookie.Value) {
				next(w, r)
				return
			}
			http.Error(w, `{"error":"CSRF_REQUIRED"}`, http.StatusForbidden)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "auth", Result: "denied"})
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
	}
}

func (s *server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		accounts, err := s.store.ListAccounts()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID    string `json:"id"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	acc, err := s.store.CreateAccount(req.ID, req.Notes)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "account.create", ObjectID: acc.ID, Result: "ok"})
	writeJSON(w, http.StatusCreated, acc)
}

func (s *server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.ID == "" {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: account ID required"))
		return
	}
	if err := s.store.ArchiveAccount(req.ID); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "account.archive", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]string{"archived": req.ID})
}

func (s *server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		devices, err := s.store.ListDevices()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
	case http.MethodPost:
		var req struct {
			AccountID string `json:"account_id"`
			Name      string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		dev, secret, err := s.store.CreateDevice(req.AccountID, req.Name)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "device.enroll", ObjectID: dev.ID, Result: "ok"})
		// the enrollment secret is shown once and never stored in plaintext
		writeJSON(w, http.StatusCreated, map[string]any{"device": dev, "enrollment_secret": secret})
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeDevice(req.ID); err != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "device.revoke", ObjectID: req.ID, Result: "error", Detail: err.Error()})
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "device.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

func (s *server) handleNodeAccessPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input nodeaccess.Input
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&input); err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: invalid node access request"))
		return
	}
	plan, err := nodeaccess.Build(input)
	if err != nil {
		writeErr(w, fmt.Errorf("VALIDATION_FAILED: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, struct {
		nodeaccess.Plan
		LocalHelper bool `json:"local_helper"`
	}{Plan: plan, LocalHelper: s.nodeAccessSocket != ""})
}

func (s *server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes, err := s.store.ListNodes()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
	case http.MethodPost:
		var req struct {
			ID       string `json:"id"`
			Country  string `json:"country"`
			Role     string `json:"role"`
			Priority int    `json:"priority"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		n, err := s.store.AddNode(req.ID, req.Country, req.Role, req.Priority)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "node.add", ObjectID: n.ID, Result: "ok"})
		writeJSON(w, http.StatusCreated, n)
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleNodeIngress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID      string `json:"id"`
		Address string `json:"address"`
		SNI     string `json:"sni"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "VALIDATION_FAILED"})
		return
	}
	if err := s.store.SetNodeIngress(req.ID, req.Address, req.SNI); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "node.ingress", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"set": req.ID})
}

func (s *server) handleNodeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeNode(req.ID); err != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "node.revoke", ObjectID: req.ID, Result: "error", Detail: err.Error()})
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "node.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.audit.Tail(200)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// pageLang resolves the UI language from the cookie or default ru.
func pageLang(r *http.Request) string {
	if c, err := r.Cookie("ara_lang"); err == nil && c.Value == "en" {
		return "en"
	}
	return "ru"
}

func (s *server) handleInvites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		invites, err := s.store.ListInvites()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
	case http.MethodPost:
		var req struct {
			DeviceID   string `json:"device_id"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		if req.TTLSeconds <= 0 || req.TTLSeconds > 7*24*3600 {
			req.TTLSeconds = 24 * 3600
		}
		inv, token, err := s.store.CreateInvite(req.DeviceID, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "invite.create", ObjectID: inv.ID, Result: "ok"})
		// the plaintext token is returned once and never stored
		writeJSON(w, http.StatusCreated, map[string]any{"invite": inv, "token": token})
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleInviteRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeInvite(req.ID); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "invite.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

// handleInviteRedeem is the PUBLIC single-use endpoint: bounded body,
// bounded token length, constant-time hash compare via the store.
func (s *server) handleInviteRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || len(req.Token) > 128 || req.Token == "" {
		http.Error(w, `{"error":"AUTH_FAILED: invite is invalid, expired, revoked or already used"}`, http.StatusUnauthorized)
		return
	}
	dev, err := s.store.RedeemInvite(req.Token)
	if err != nil {
		s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "invite.redeem", Result: "denied"})
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: r.RemoteAddr, Action: "invite.redeem", ObjectID: dev.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"device": dev})
}

// handleLinks manages Edge→Exit associations with per-hop transport.
func (s *server) handleLinks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		links, err := s.store.ListLinks()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"links": links})
	case http.MethodPost:
		var req struct {
			EdgeID    string  `json:"edge_id"`
			ExitID    string  `json:"exit_id"`
			Transport string  `json:"transport"`
			Priority  int     `json:"priority"`
			ProfileID *string `json:"profile_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		if local := os.Getenv("ARA_LOCAL_SUB_EDGE"); local != "" && local == req.EdgeID && os.Getenv("ARA_REQUIRE_SERVING_ROUTES") == "1" {
			if _, err := s.store.AllocateRoutePort(req.EdgeID, req.ExitID); err != nil {
				writeErr(w, err)
				return
			}
		}

		l, err := s.store.AddLink(req.EdgeID, req.ExitID, req.Transport, req.Priority, req.ProfileID)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "link.add", ObjectID: l.ID, Result: "ok"})
		writeJSON(w, http.StatusCreated, l)
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

func (s *server) handleLinkRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeLink(req.ID); err != nil {
		writeErr(w, err)
		return
	}
	s.audit.Append(controlstore.AuditEntry{Actor: "operator", Action: "link.revoke", ObjectID: req.ID, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": req.ID})
}

// handlePolicy exposes the routing policy through the shared service layer
// (GET current; POST validates and stages a plan with the given hash back).
func (s *server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, err := svc.PolicyGet()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodPost:
		var candidate map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&candidate); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		b, _ := json.Marshal(candidate)
		var pol policy.Policy
		if err := json.Unmarshal(b, &pol); err != nil {
			http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusBadRequest)
			return
		}
		plan, hash, err := svc.PolicyPlan(&pol, time.Now().UTC())
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"plan_id": plan.ID, "plan_hash": hash, "expires_at": plan.ExpiresAt,
			"next": "POST /api/v1/policy/apply with plan_id and plan_hash"})
	default:
		http.Error(w, `{"error":"VALIDATION_FAILED"}`, http.StatusMethodNotAllowed)
	}
}

// handleLimits exposes the limits view through the shared service layer.
func (s *server) handleLimits(w http.ResponseWriter, r *http.Request) {
	svc, err := s.service()
	if err != nil {
		writeErr(w, err)
		return
	}
	view, err := svc.LimitsShow()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleTLSStatus reports the wizard store state.
func (s *server) handleTLSStatus(w http.ResponseWriter, r *http.Request) {
	st := tlswizard.Store{Dir: filepath.Join(s.stateDir, "tls")}
	view := map[string]any{"active": nil, "store_cert_path": st.ActiveCertificatePath(), "panel_tls": "external_proxy"}
	if s.httpsEnabled {
		view["panel_tls"] = "native_https"
	}
	if s.edgeStatusPath != "" {
		if observed, err := readEdgeObservation(s.edgeStatusPath, time.Now()); err == nil {
			view["edge_tls"] = observed.TLS
		}
	}
	imp, err := st.Active()
	if err == nil {
		view["active"] = imp
		view["renewal_due"] = !time.Now().Add(30 * 24 * time.Hour).Before(imp.NotAfter)
	}
	writeJSON(w, http.StatusOK, view)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	code := http.StatusBadRequest
	switch {
	case strings.Contains(msg, "AUTH_FAILED"):
		code = http.StatusUnauthorized
	case strings.Contains(msg, "CONFLICT"), strings.Contains(msg, "PLAN_STALE"):
		code = http.StatusConflict
	case strings.Contains(msg, "not found"):
		code = http.StatusNotFound
	}
	writeJSON(w, code, map[string]any{"error": msg})
}

// isLoopbackListen refuses non-loopback bind addresses at startup: this
// process is the local management plane only.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolveDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + "/.ara-control", nil
}
