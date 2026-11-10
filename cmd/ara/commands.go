package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"aravpn/core/plan"
	"aravpn/core/policy"
	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/ipc"
	"aravpn/internal/service"
)

func cmdPolicy(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara policy get|validate|plan|apply ...")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "get":
		p, err := svc.PolicyGet()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, p)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(p); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		return schema.ExitOK
	case "validate":
		fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		file := fs.String("file", "", "policy JSON file")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		p, err := readPolicyFile(*file)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := svc.PolicyValidate(p); err != nil {
			return fail(g, lang, schema.CodePolicyInvalid, "error."+schema.CodePolicyInvalid, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"valid": true, "rules": len(p.Rules), "revision": p.Revision})
		}
		fmt.Println(i18n.T(lang, "policy.validate.ok", map[string]any{"count": len(p.Rules)}))
		return schema.ExitOK

	case "plan":
		fs := flag.NewFlagSet("policy plan", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		file := fs.String("file", "", "policy JSON file")
		output := fs.String("output", "", "plan output file")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *file == "" || *output == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--file and --output required"}, nil)
		}
		p, err := readPolicyFile(*file)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		planDoc, hash, err := svc.PolicyPlan(p, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodePolicyInvalid, "error."+schema.CodePolicyInvalid, nil, err)
		}
		if err := writePlanFile(*output, planDoc, hash); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan_id": planDoc.ID, "plan_hash": hash, "expires_at": planDoc.ExpiresAt, "preconditions": planDoc.Preconditions})
		}
		fmt.Println(i18n.T(lang, "policy.plan.created", map[string]any{"id": planDoc.ID, "expires_at": planDoc.ExpiresAt.Format(time.RFC3339)}))
		fmt.Fprintf(os.Stderr, "plan_hash: %s\n", hash)
		return schema.ExitOK

	case "apply":
		fs := flag.NewFlagSet("policy apply", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		planFile := fs.String("plan", "", "plan JSON file")
		hash := fs.String("expected-hash", "", "plan hash as printed by plan")
		_ = fs.Bool("non-interactive", false, "accepted for agent compatibility; this CLI never prompts")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *planFile == "" || *hash == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--plan and --expected-hash required"}, nil)
		}
		planDoc, err := readPlanFile(*planFile)
		if err != nil {
			return fail(g, lang, schema.CodePlanStale, "error."+schema.CodePlanStale, nil, err)
		}
		res, err := svc.PolicyApply(planDoc.ID, *hash)
		if err != nil {
			return applyErrToExit(g, lang, err)
		}
		if g.json {
			return okJSON(g, res)
		}
		fmt.Println(i18n.T(lang, "policy.apply.ok", map[string]any{"revision": res.NewRevision}))
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "usage: ara policy get|validate|plan|apply")
	return schema.ExitUsage
}

func cmdLimits(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara limits show|plan|apply")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "show":
		view, err := svc.LimitsShow()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, view)
		}
		fmt.Println(i18n.T(lang, "limits.show.title", map[string]any{"scope": view.AccountID + "/" + view.DeviceID}))
		fmt.Println(i18n.T(lang, "limits.rate_dl", map[string]any{"rate": bpsOrUnlimited(view.DownloadBPS)}))
		fmt.Println(i18n.T(lang, "limits.rate_ul", map[string]any{"rate": bpsOrUnlimited(view.UploadBPS)}))
		if view.Exhausted {
			fmt.Println(i18n.T(lang, "error.QUOTA_EXCEEDED", map[string]any{"reset_at": view.ResetAt.Format(time.RFC3339)}))
		} else if view.Remaining != nil {
			fmt.Println(i18n.T(lang, "usage.used", map[string]any{"used": view.Used, "limit": deref(view.AccountTotal, view.DeviceTotal)}))
			fmt.Println(i18n.T(lang, "usage.reset", map[string]any{"reset_at": view.ResetAt.Format(time.RFC3339), "tz": view.Timezone}))
		} else {
			fmt.Println(i18n.T(lang, "status.quota_unlimited", nil))
		}
		return schema.ExitOK

	case "plan":
		fs := flag.NewFlagSet("limits plan", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		file := fs.String("file", "", "limits JSON file")
		output := fs.String("output", "", "plan output file")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *file == "" || *output == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--file and --output required"}, nil)
		}
		cfg, err := readLimitsFile(*file)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		planDoc, hash, err := svc.LimitsPlan(cfg, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := writePlanFile(*output, planDoc, hash); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan_id": planDoc.ID, "plan_hash": hash, "expires_at": planDoc.ExpiresAt})
		}
		fmt.Println(i18n.T(lang, "policy.plan.created", map[string]any{"id": planDoc.ID, "expires_at": planDoc.ExpiresAt.Format(time.RFC3339)}))
		fmt.Fprintf(os.Stderr, "plan_hash: %s\n", hash)
		return schema.ExitOK

	case "apply":
		fs := flag.NewFlagSet("limits apply", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		planFile := fs.String("plan", "", "plan JSON file")
		hash := fs.String("expected-hash", "", "plan hash")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *planFile == "" || *hash == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--plan and --expected-hash required"}, nil)
		}
		planDoc, err := readPlanFile(*planFile)
		if err != nil {
			return fail(g, lang, schema.CodePlanStale, "error."+schema.CodePlanStale, nil, err)
		}
		res, err := svc.LimitsApply(planDoc.ID, *hash)
		if err != nil {
			return applyErrToExit(g, lang, err)
		}
		if g.json {
			return okJSON(g, res)
		}
		fmt.Println(i18n.T(lang, "limits.apply.ok", nil))
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "usage: ara limits show|plan|apply")
	return schema.ExitUsage
}

func cmdNode(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara node list | node add --id ID --country CC --role ru|foreign [--priority N] | node remove --id ID | node transport capabilities|list|add-profile|revoke-profile|render")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "backbone":
		return cmdBackbone(g, tail[1:], lang)
	case "access":
		return cmdNodeAccess(g, tail[1:], lang)
 case "check":
 return cmdNodeCheck(svc,g,tail[1:],lang)
	case "list":
		view, err := svc.Status()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"nodes": view.Topology})
		}
		if len(view.Topology) == 0 {
			fmt.Println(i18n.T(lang, "node.empty", nil))
			return schema.ExitOK
		}
		fmt.Println(i18n.T(lang, "node.list.title", map[string]any{"count": len(view.Topology)}))
		for _, n := range view.Topology {
			fmt.Println("  " + i18n.T(lang, "node.entry", map[string]any{
				"id": n.ID, "country": n.Country, "priority": n.Priority, "health": n.Health,
			}))
		}
		return schema.ExitOK
	case "add":
		return cmdNodeAdd(svc, g, tail[1:], lang)
	case "remove":
		return cmdNodeRemove(svc, g, tail[1:], lang)
	case "transport":
		return cmdNodeTransport(svc, g, tail[1:], lang)
	case "edge-config":
		return cmdNodeEdgeConfig(svc, g, tail[1:], lang)
	case "set-ingress":
		fs := flag.NewFlagSet("node set-ingress", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "node id")
		addr := fs.String("addr", "", "client ingress host:port (empty disables)")
		sni := fs.String("sni", "", "ingress TLS server_name")
		if err := fs.Parse(tail[1:]); err != nil || *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		st2, err := svc.OpenControlStore()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		defer st2.Close()
		if err := st2.SetNodeIngress(*id, *addr, *sni); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"node": *id, "ingress_addr": *addr})
		}
		fmt.Println(i18n.T(lang, "topology.node_ingress_set", map[string]any{"id": *id, "addr": *addr}))
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown node subcommand")
	return schema.ExitUsage
}

// engineCall dials the local agent socket and invokes one engine method.
// The agent daemon owns the engine process lifetime, so connect/disconnect
// are agent-mediated: without a running agent they are UNAVAILABLE, not
// silently executed in the CLI process.
func engineCall(g *globals, method string, params any) (json.RawMessage, *string, error) {
	st := service.StateDir{Root: g.stateDir}
	if st.Root == "" {
		def, err := service.DefaultStateDir()
		if err != nil {
			return nil, nil, err
		}
		st = def
	}
	c, err := ipc.Dial(st.AgentSock())
	if err != nil {
		return nil, nil, fmt.Errorf("agent not reachable at %s (start ara-agent first): %w", st.AgentSock(), err)
	}
	defer c.Close()
	res, ierr, err := c.Call(method, params)
	if err != nil {
		return nil, nil, err
	}
	if ierr != nil {
		return nil, &ierr.Code, fmt.Errorf("%s: %s", ierr.Code, ierr.Message)
	}
	return res, nil, nil
}

func cmdSetup(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	if len(tail) == 0 || (tail[0] != "plan" && tail[0] != "apply") {
		fmt.Fprintln(os.Stderr, "usage: ara setup plan --file setup.json --output plan.json | setup apply --plan plan.json --expected-hash <hash>")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "plan":
		fs := flag.NewFlagSet("setup plan", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		file := fs.String("file", "", "setup JSON file")
		output := fs.String("output", "", "plan output file")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *file == "" || *output == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--file and --output required"}, nil)
		}
		b, err := os.ReadFile(*file)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		var doc service.SetupDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		planDoc, hash, err := svc.SetupPlan(&doc, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := writePlanFile(*output, planDoc, hash); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan_id": planDoc.ID, "plan_hash": hash, "expires_at": planDoc.ExpiresAt, "preconditions": planDoc.Preconditions})
		}
		fmt.Println(i18n.T(lang, "policy.plan.created", map[string]any{"id": planDoc.ID, "expires_at": planDoc.ExpiresAt.Format(time.RFC3339)}))
		fmt.Fprintf(os.Stderr, "plan_hash: %s\n", hash)
		return schema.ExitOK
	case "apply":
		fs := flag.NewFlagSet("setup apply", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		planFile := fs.String("plan", "", "plan JSON file")
		hash := fs.String("expected-hash", "", "plan hash")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *planFile == "" || *hash == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--plan and --expected-hash required"}, nil)
		}
		planDoc, err := readPlanFile(*planFile)
		if err != nil {
			return fail(g, lang, schema.CodePlanStale, "error."+schema.CodePlanStale, nil, err)
		}
		res, err := svc.SetupApply(planDoc.ID, *hash)
		if err != nil {
			return applyErrToExit(g, lang, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"applied": res.Applied, "summary": res.Summary})
		}
		fmt.Println(i18n.T(lang, "setup.apply.ok", nil))
		return schema.ExitOK
	}
	return schema.ExitUsage
}

func cmdConnect(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profile := fs.String("profile", "default", "profile name in <state>/profiles/")
	mode := fs.String("mode", "", "capture for this session: tun or proxy (default: profile setting)")
	_ = fs.Bool("non-interactive", false, "accepted for agent compatibility; this CLI never prompts")
	if err := fs.Parse(tail); err != nil {
		return emitUsageError(g, err)
	}
	if *mode != "" && *mode != "tun" && *mode != "proxy" {
		return emitUsageError(g, fmt.Errorf("--mode must be tun or proxy"))
	}
	method := "connect"
	if *mode != "" {
		method = "connect.mode"
	}
	res, code, err := engineCall(g, method, map[string]any{"profile": *profile, "mode": *mode})
	if err != nil {
		c := schema.CodeUnavailable
		if code != nil && *code == "CONFLICT" {
			c = schema.CodeConflict
		}
		if code != nil && *code == "VALIDATION_FAILED" {
			c = schema.CodeValidation
		}
		return fail(g, lang, c, "error."+c, nil, err)
	}
	var view map[string]any
	_ = json.Unmarshal(res, &view)
	if g.json {
		return okJSON(g, view)
	}
	fmt.Println(i18n.T(lang, "connect.ok", map[string]any{"profile": view["profile_name"], "pid": view["pid"]}))
	return schema.ExitOK
}

func cmdDisconnect(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	res, code, err := engineCall(g, "disconnect", nil)
	if err != nil {
		c := schema.CodeUnavailable
		if code != nil && *code == "NOT_CONNECTED" {
			c = schema.CodeConflict
		}
		return fail(g, lang, c, "error."+c, nil, err)
	}
	var view map[string]any
	_ = json.Unmarshal(res, &view)
	if g.json {
		return okJSON(g, view)
	}
	fmt.Println(i18n.T(lang, "disconnect.ok", nil))
	return schema.ExitOK
}

// applyErrToExit maps plan-discipline failures to documented exit codes.
func applyErrToExit(g *globals, lang i18n.Lang, err error) int {
	msg := err.Error()
	switch {
	case contains(msg, "PLAN_EXPIRED"):
		return fail(g, lang, schema.CodePlanExpired, "error."+schema.CodePlanExpired, map[string]any{"expires_at": extractAfter(msg, "expired at ")}, nil)
	case contains(msg, "PLAN_STALE"):
		return fail(g, lang, schema.CodePlanStale, "error."+schema.CodePlanStale, nil, err)
	case contains(msg, "VERIFICATION_FAILED"):
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
	case contains(msg, "CONFLICT"):
		return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
	case contains(msg, "POLICY_INVALID"):
		return fail(g, lang, schema.CodePolicyInvalid, "error."+schema.CodePolicyInvalid, nil, err)
	default:
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && stringsIndex(s, sub) >= 0 }

func stringsIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func extractAfter(s, marker string) string {
	i := stringsIndex(s, marker)
	if i < 0 {
		return ""
	}
	return s[i+len(marker):]
}

func bpsOrUnlimited(v *int64) string {
	if v == nil {
		return "unlimited"
	}
	return fmt.Sprintf("%d bit/s (%.1f Mbit/s)", *v, float64(*v)/1e6)
}

func deref(vals ...*int64) int64 {
	for _, v := range vals {
		if v != nil {
			return *v
		}
	}
	return 0
}

func readPolicyFile(path string) (p *policy.Policy, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc policy.Policy
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &doc, nil
}

func readLimitsFile(path string) (*service.LimitsConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg service.LimitsConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// planFileDoc is the on-disk plan artifact: the reviewed hash travels
// beside the plan document.
type planFileDoc struct {
	PlanHash string    `json:"plan_hash"`
	Plan     plan.Plan `json:"plan"`
}

func readPlanFile(path string) (*plan.Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc planFileDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Plan.ID == "" {
		return nil, fmt.Errorf("%s: plan document has no id", path)
	}
	return &doc.Plan, nil
}

func writePlanFile(path string, plan any, hash string) error {
	doc := map[string]any{"plan_hash": hash, "plan": plan}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
