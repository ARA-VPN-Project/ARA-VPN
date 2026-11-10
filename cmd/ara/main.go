// Command ara is the ARA VPN CLI: a full interface for humans and
// automation agents (docs/CLI_AUTOMATION.md). --json prints exactly one
// versioned envelope to stdout; human text uses --lang ru|en; exit codes
// are documented in core/schema.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

type globals struct {
	json     bool
	lang     string
	stateDir string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	g := &globals{}
	fs := flag.NewFlagSet("ara", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&g.json, "json", false, "machine mode: one versioned JSON object on stdout")
	fs.StringVar(&g.lang, "lang", "", "human output language ru|en (default: system locale)")
	fs.StringVar(&g.stateDir, "state-dir", os.Getenv("ARA_STATE_DIR"), "state directory (default ~/.ara)")
	if len(args) == 0 {
		usage()
		return schema.ExitUsage
	}
	// global flags are recognized anywhere on the line; the first
	// non-global argument is the subcommand
	head, tail := splitGlobals(args, g)
	// splitGlobals already consumed the global flags; parsing the rest
	// here would reject subcommand flags (e.g. connect --profile) that
	// belong to the subcommand's own flagset
	_ = fs
	lang := humanLang(g.lang)

	svc, serr := openService(g)
	serviceOpenErr = serr
	cmds := map[string]func() int{
		"status":        func() int { return cmdStatus(svc, g, lang) },
		"backup":        func() int { return cmdBackup(g, tail, lang) },
		"doctor":        func() int { return cmdDoctor(svc, g, lang) },
		"route":         func() int { return cmdRoute(svc, g, tail, lang) },
		"policy":        func() int { return cmdPolicy(svc, g, tail, lang) },
		"limits":        func() int { return cmdLimits(svc, g, tail, lang) },
		"node":          func() int { return cmdNode(svc, g, tail, lang) },
		"link":          func() int { return cmdLink(svc, g, tail, lang) },
		"topology":      func() int { return cmdTopology(svc, g, tail, lang) },
		"edge":          func() int { return cmdEdgeSync(svc, g, tail, lang) },
		"panel":         func() int { return cmdPanel(svc, g, tail, lang) },
		"subscription":  func() int { return cmdSubscription(svc, g, tail, lang) },
		"account":       func() int { return cmdAccount(svc, g, tail, lang) },
		"follow":        func() int { return cmdSubscriptionFollow(svc, g, tail, lang) },
		"autoconfigure": func() int { return cmdSubscriptionAutoconfigure(svc, g, tail, lang) },
		"invite":        func() int { return cmdInvite(svc, g, tail, lang) },
		"enroll":        func() int { return cmdEnroll(svc, g, tail, lang) },
		"connect":       func() int { return cmdConnect(svc, g, tail, lang) },
		"disconnect":    func() int { return cmdDisconnect(svc, g, tail, lang) },
		"tls":           func() int { return cmdTLS(svc, g, tail, lang) },
		"update":        func() int { return cmdUpdate(svc, g, tail, lang) },
		"setup":         func() int { return cmdSetup(svc, g, tail, lang) },
		"netplan":       func() int { return cmdNetplan(svc, g, tail, lang) },
		"speedtest":     func() int { return cmdSpeedtest(svc, g, tail, lang) },
		"diagnose":      func() int { return unsupportedCmd(g, "diagnose", lang) },
		"version":       func() int { return cmdVersion(g, lang) },
		"help":          func() int { usage(); return schema.ExitOK },
	}
	fn, ok := cmds[head]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", head)
		usage()
		return schema.ExitUsage
	}
	return fn()
}

// splitGlobals removes recognized global flags from anywhere in args and
// returns the subcommand plus the remaining arguments.
func splitGlobals(args []string, g *globals) (string, []string) {
	var out []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			g.json = true
		case "--lang":
			if i+1 < len(args) {
				g.lang = args[i+1]
				i++
			}
		case "--state-dir":
			if i+1 < len(args) {
				g.stateDir = args[i+1]
				i++
			}
		default:
			out = append(out, args[i])
		}
	}
	if len(out) == 0 {
		return "", nil
	}
	return out[0], out[1:]
}

func humanLang(flagVal string) i18n.Lang {
	if flagVal == "ru" {
		return i18n.RU
	}
	if flagVal == "en" {
		return i18n.EN
	}
	return i18n.Resolve(os.Getenv("LANG"))
}

func openService(g *globals) (*service.Service, error) {
	st, err := resolveStateDir(g.stateDir)
	if err != nil {
		return nil, err
	}
	return service.New(st)
}

func resolveStateDir(flagVal string) (service.StateDir, error) {
	if flagVal != "" {
		return service.StateDir{Root: flagVal}, nil
	}
	return service.DefaultStateDir()
}

// emitJSON prints the single envelope; errors keep documented exit codes.
func emitJSON(g *globals, data any, envErr *schema.Envelope) int {
	var env schema.Envelope
	if envErr != nil {
		env = *envErr
	} else {
		env = schema.NewEnvelope(data)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return schema.ExitUsage
	}
	if env.Error != nil {
		return schema.ExitCodeFor(env.Error.Code)
	}
	return schema.ExitOK
}

// emitHuman prints localized text; on error prints localized message with
// the stable code and returns the documented exit code.
func emitHuman(lang i18n.Lang, text string, code string, params map[string]any) int {
	if code == "" {
		fmt.Println(text)
		return schema.ExitOK
	}
	msg := i18n.T(lang, "error."+code, params)
	fmt.Fprintf(os.Stderr, "%s [%s]\n", msg, code)
	return schema.ExitCodeFor(code)
}

func fail(g *globals, lang i18n.Lang, code, messageKey string, params map[string]any, err error) int {
	if params == nil {
		params = map[string]any{}
	}
	if err != nil {
		params["detail"] = err.Error()
	} else if params["detail"] == nil {
		params["detail"] = ""
	}
	if g.json {
		return emitJSON(g, nil, errEnvelope(code, messageKey, params))
	}
	return emitHuman(lang, "", code, params)
}

func errEnvelope(code, messageKey string, params map[string]any) *schema.Envelope {
	e := schema.NewErrorEnvelope(code, messageKey, false, params)
	return &e
}

func okJSON(g *globals, data any) int { return emitJSON(g, data, nil) }

func unsupportedCmd(g *globals, name string, lang i18n.Lang) int {
	return fail(g, lang, schema.CodeUnsupported, "error."+schema.CodeUnsupported,
		map[string]any{"capability": name}, nil)
}

func cmdVersion(g *globals, lang i18n.Lang) int {
	v := map[string]any{"name": "ara", "version": version, "api_version": schema.APIVersion, "policy_schema": schema.SchemaVersion}
	if g.json {
		return okJSON(g, v)
	}
	fmt.Printf("ara %s (api %s, policy schema v%d)\n", version, schema.APIVersion, schema.SchemaVersion)
	return schema.ExitOK
}

var version = "0.1.1-dev"

func cmdStatus(svc *service.Service, g *globals, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	view, err := svc.Status()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	if g.json {
		return okJSON(g, view)
	}
	fmt.Println(i18n.T(lang, "status.mode."+view.Mode, map[string]any{
		"exit": orDash(view.ExitID), "country": orDash(view.Country), "reason": view.Reason,
	}))
	fmt.Println(i18n.T(lang, "status.policy_revision", map[string]any{"revision": view.PolicyRevision}))
	return schema.ExitOK
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func usage() {
	fmt.Fprint(os.Stderr, `ara — ARA VPN command line

Global flags: --json | --lang ru|en | --state-dir DIR

Commands:
  ara status                          current factual mode and topology
  ara doctor                          read-only local checks (incl. network path to ingress)
  ara route explain --domain D [--ip IP] [--proto tcp|udp] [--port N]
  ara policy validate|plan|apply      routing policy (DIRECT/RU/foreign, fallback, BLOCK)
  ara limits show|plan|apply          account/device rate and volume quotas
  ara node list | node add | node remove
  ara backup create|verify|restore    offline native node state
  ara node access plan|apply|remove    scoped node firewall access
  ara node backbone apply|status       managed OpenVPN / WireGuard transit
  ara node transport capabilities|list|add-profile|revoke-profile|render
  ara link list|add|set-profile|remove        (Edge→Exit, typed transport profiles)
  ara topology plan|apply             declarative nodes/profiles/links document
  ara invite ...                      client enrollment invitations (QR)
  ara speedtest run|status|history|cancel|export   (client-edge | edge-exit | e2e)
  ara version

connect/disconnect, tls, update, setup and netplan manage the client side.
Control Center (ara-control) exposes the same service layer over HTTP + panel.
`)
}

func emitUsageError(g *globals, err error) int {
	if g.json {
		return emitJSON(g, nil, errEnvelope(schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": err.Error()}))
	}
	fmt.Fprintln(os.Stderr, err)
	return schema.ExitUsage
}

var serviceOpenErr error

func cmdDoctor(svc *service.Service, g *globals, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail,omitempty"`
	}
	var checks []check
	add := func(name string, err error) {
		c := check{Name: name, OK: err == nil}
		if err != nil {
			c.Detail = err.Error()
		}
		checks = append(checks, c)
	}
	add("state_dir", svc.State.Ensure())
	if pol, err := svc.LoadPolicyStore(); err == nil {
		_, err = pol.Load()
		add("policy_load", err)
	} else {
		add("policy_load", err)
	}
	_, err := svc.LoadTopology()
	add("topology_load", err)
	_, err = svc.LoadLimitsConfig()
	add("limits_load", err)
	add("locales", i18n.LoadError())
	if err := i18n.LoadError(); err != nil {
		add("locales", err)
	}
	// network path to the ingress: route/interface, DNS, IPv6, MTU —
	// strictly read-only facts (cmd/ara/doctor_net.go)
	for _, c := range networkChecks(svc) {
		ok, detail := c.OK, c.Detail
		add(c.Name, func() error {
			if ok {
				return nil
			}
			return fmt.Errorf("%s", detail)
		}())
	}
	allOK := true
	for _, c := range checks {
		if !c.OK {
			allOK = false
		}
	}
	if g.json {
		return okJSON(g, map[string]any{"ok": allOK, "checks": checks})
	}
	fmt.Println(i18n.T(lang, "doctor.title", nil))
	for _, c := range checks {
		if c.OK {
			fmt.Println("  " + i18n.T(lang, "doctor.check_ok", map[string]any{"name": c.Name}))
		} else {
			fmt.Println("  " + i18n.T(lang, "doctor.check_fail", map[string]any{"name": c.Name, "detail": c.Detail}))
		}
	}
	if allOK {
		return schema.ExitOK
	}
	return schema.ExitUnavailable
}

func cmdRoute(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) < 1 || tail[0] != "explain" {
		fmt.Fprintln(os.Stderr, "usage: ara route explain --domain D [--ip IP] [--proto tcp|udp] [--port N]")
		return schema.ExitUsage
	}
	fs := flag.NewFlagSet("route explain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	domain := fs.String("domain", "", "destination domain")
	ip := fs.String("ip", "", "destination IP")
	proto := fs.String("proto", "tcp", "transport protocol")
	port := fs.Int("port", 443, "destination port")
	if err := fs.Parse(tail[1:]); err != nil {
		return emitUsageError(g, err)
	}
	if *domain == "" && *ip == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "domain or ip required"}, nil)
	}
	view, err := svc.RouteExplain(*domain, *ip, strings.ToLower(*proto), *port)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if g.json {
		return okJSON(g, view)
	}
	fmt.Println(i18n.T(lang, "route.explain.title", nil))
	fmt.Println(i18n.T(lang, "route.rule_id", map[string]any{"rule": orDash(str(view["matched_rule_id"]))}))
	fmt.Println(i18n.T(lang, "route.desired", map[string]any{"action": str(view["desired_action"])}))
	fmt.Println(i18n.T(lang, "route.actual", map[string]any{"actual": str(view["actual_action"]), "exit": orDash(str(view["exit_id"]))}))
	fmt.Println(i18n.T(lang, "route.reason", map[string]any{"reason": str(view["reason_code"])}))
	fmt.Println(i18n.T(lang, "route.dns_scope", map[string]any{"scope": str(view["dns_scope"])}))
	return schema.ExitOK
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
