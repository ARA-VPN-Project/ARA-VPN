// Command ara-agent is the local ARA agent daemon: it owns the state
// directory and serves the typed IPC method table over a private Unix
// socket. It performs no network data-plane work in this build and never
// executes shell commands (docs/SECURITY.md A16).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"aravpn/core/policy"
	"aravpn/internal/clientengine"
	"aravpn/internal/ipc"
	"aravpn/internal/service"
)

func main() {
	stateDir := flag.String("state-dir", os.Getenv("ARA_STATE_DIR"), "state directory (default ~/.ara)")
	flag.Parse()

	st, err := resolveDir(*stateDir)
	if err != nil {
		log.Fatalf("state dir: %v", err)
	}
	svc, err := service.New(st)
	if err != nil {
		log.Fatalf("service: %v", err)
	}

	eng := clientengine.New(st.Root)
	// B39: the live client policy drives the engine's DIRECT/BLOCK route
	// rules at every connect (a policy apply reaches the runtime without
	// re-running setup).
	eng.SetPolicyProvider(func() (*policy.Policy, error) { return svc.PolicyGet() })
	methods := map[string]ipc.Handler{
		"status":              svcHandler(svc.Status),
		"route.explain":       routeExplainHandler(svc),
		"policy.get":          svcHandler(svc.PolicyGet),
		"policy.validate":     validateHandler(svc),
		"limits.show":         svcHandler(svc.LimitsShow),
		"doctor":              doctorHandler(svc),
		"engine.status":       engineStatusHandler(eng),
		"connect":             connectHandler(eng),
		"connect.mode":        connectHandler(eng),
		"disconnect":          disconnectHandler(eng),
		"subscription.status": svcHandler(svc.SubscriptionRefreshStatus),
		"subscription.refresh": func(ctx context.Context, raw json.RawMessage) (any, *ipc.IpcError) {
			res, err := svc.SubscriptionRefreshOnce()
			if err != nil {
				return nil, toIpcErr(err)
			}
			return res, nil
		},
		"subscription.configure": func(ctx context.Context, raw json.RawMessage) (any, *ipc.IpcError) {
			var cfg service.SubscriptionAutoRefreshConfig
			if len(raw) == 0 {
				return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: "config required"}
			}
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: err.Error()}
			}
			if err := svc.SubscriptionFollowConfigure(cfg); err != nil {
				return nil, toIpcErr(err)
			}
			return map[string]any{"configured": true}, nil
		},
	}

	sock := st.AgentSock()
	srv, err := ipc.NewServer(sock, methods)
	if err != nil {
		log.Fatalf("ipc: %v", err)
	}
	// local client UI on loopback (opt-in port): controls THIS tunnel only
	if port := os.Getenv("ARA_CLIENT_UI"); port != "" {
		aw := &agentWeb{eng: eng, targets: clientTargets(st.Root), svc: svc}
		mux := http.NewServeMux()
		aw.routes(mux)
		go func() {
			log.Printf("client ui on 127.0.0.1:%s", port)
			if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
				log.Printf("client ui: %v", err)
			}
		}()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("ara-agent listening on %s (state %s)", sock, st.Root)
	if err := srv.Serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// clientTargets reads ping/speedtest targets from the active profile.
func clientTargets(root string) func() []string {
	return func() []string {
		b, err := os.ReadFile(root + "/profiles/default.json")
		if err != nil {
			return nil
		}
		var p struct {
			ServerAddr string `json:"server_addr"`
		}
		if json.Unmarshal(b, &p) != nil {
			return nil
		}
		host := strings.Split(p.ServerAddr, ":")[0]
		return []string{host + ":8000", p.ServerAddr}
	}
}

func resolveDir(flagVal string) (service.StateDir, error) {
	if flagVal != "" {
		return service.StateDir{Root: flagVal}, nil
	}
	return service.DefaultStateDir()
}

func svcHandler[Res any](fn func() (Res, error)) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, *ipc.IpcError) {
		res, err := fn()
		if err != nil {
			return nil, toIpcErr(err)
		}
		return res, nil
	}
}

func routeExplainHandler(svc *service.Service) ipc.Handler {
	type params struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
		Proto  string `json:"proto"`
		Port   int    `json:"port"`
	}
	return func(ctx context.Context, raw json.RawMessage) (any, *ipc.IpcError) {
		var p params
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: err.Error()}
			}
		}
		res, err := svc.RouteExplain(p.Domain, p.IP, p.Proto, p.Port)
		if err != nil {
			return nil, toIpcErr(err)
		}
		return res, nil
	}
}

func validateHandler(svc *service.Service) ipc.Handler {
	return func(ctx context.Context, raw json.RawMessage) (any, *ipc.IpcError) {
		var policyDoc map[string]any
		if err := json.Unmarshal(raw, &policyDoc); err != nil {
			return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: err.Error()}
		}
		b, _ := json.Marshal(policyDoc)
		var cand = decodePolicy(b)
		if err := svc.PolicyValidate(&cand); err != nil {
			return nil, toIpcErr(err)
		}
		return map[string]any{"valid": true}, nil
	}
}

func doctorHandler(svc *service.Service) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, *ipc.IpcError) {
		if err := svc.State.Ensure(); err != nil {
			return nil, toIpcErr(err)
		}
		if _, err := svc.Status(); err != nil {
			return map[string]any{"ok": false, "detail": err.Error()}, nil
		}
		return map[string]any{"ok": true}, nil
	}
}

func connectHandler(eng *clientengine.Engine) ipc.Handler {
	return func(ctx context.Context, raw json.RawMessage) (any, *ipc.IpcError) {
		var p struct {
			Profile string `json:"profile"`
			Mode    string `json:"mode"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: err.Error()}
			}
		}
		if p.Profile == "" {
			p.Profile = "default"
		}
		if p.Mode != "" && p.Mode != "tun" && p.Mode != "proxy" {
			return nil, &ipc.IpcError{Code: "VALIDATION_FAILED", Message: "mode must be tun or proxy"}
		}
		res, err := eng.StartMode(p.Profile, p.Mode)
		if err != nil {
			return nil, connectIpcErr(err)
		}
		return res, nil
	}
}

func disconnectHandler(eng *clientengine.Engine) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, *ipc.IpcError) {
		res, err := eng.Stop()
		if err != nil {
			return nil, connectIpcErr(err)
		}
		return res, nil
	}
}

func engineStatusHandler(eng *clientengine.Engine) ipc.Handler {
	return func(ctx context.Context, _ json.RawMessage) (any, *ipc.IpcError) {
		res, err := eng.Status()
		if err != nil {
			return nil, connectIpcErr(err)
		}
		return res, nil
	}
}

// connectIpcErr maps engine errors to stable codes: a live session is a
// CONFLICT, no session is NOT_CONNECTED, everything else internal.
func connectIpcErr(err error) *ipc.IpcError {
	msg := err.Error()
	switch {
	case errors.Is(err, clientengine.ErrAlreadyConnected):
		return &ipc.IpcError{Code: "CONFLICT", Message: msg}
	case errors.Is(err, clientengine.ErrNotConnected):
		return &ipc.IpcError{Code: "NOT_CONNECTED", Message: msg}
	}
	return &ipc.IpcError{Code: "INTERNAL", Message: msg}
}

func toIpcErr(err error) *ipc.IpcError {
	msg := err.Error()
	code := "INTERNAL"
	for _, c := range []string{"VALIDATION_FAILED", "POLICY_INVALID", "CONFLICT", "PLAN_STALE", "PLAN_EXPIRED", "VERIFICATION_FAILED", "UNSUPPORTED_CAPABILITY", "QUOTA_EXHAUSTED", "NO_EGRESS_AVAILABLE"} {
		if len(msg) >= len(c) && msg[:len(c)] == c {
			code = c
			break
		}
	}
	return &ipc.IpcError{Code: code, Message: msg}
}

func decodePolicy(b []byte) (p policy.Policy) {
	json.Unmarshal(b, &p)
	return
}
