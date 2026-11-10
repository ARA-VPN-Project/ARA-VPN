// Control-plane CLI commands (docs/CLI_AUTOMATION.md): full headless
// management of nodes, links, typed transport profiles and the declarative
// topology document — same service layer as the Control Center panel, JSON
// envelopes, stable exit codes, validate → plan → apply. Credential values
// are read from --password-file or stdin, never from argv or plan JSON.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"aravpn/core/transportprofile"
	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func requireSvc(svc *service.Service, g *globals, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	return -1
}

func readSecret(flagFile string, flagStdin bool) (string, error) {
	switch {
	case flagFile != "" && flagStdin:
		return "", fmt.Errorf("--password-file and --password-stdin are mutually exclusive")
	case flagFile != "":
		b, err := os.ReadFile(flagFile)
		if err != nil {
			return "", err
		}
		s := string(b)
		if len(s) > 0 && s[len(s)-1] == '\n' {
			s = s[:len(s)-1]
		}
		if s == "" {
			return "", fmt.Errorf("password file %s is empty", flagFile)
		}
		return s, nil
	case flagStdin:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		s := strings.TrimRight(string(b), "\r\n")
		if s == "" {
			return "", fmt.Errorf("empty credential on stdin")
		}
		return s, nil
	default:
		return "", fmt.Errorf("credential source required: --password-file F or --password-stdin (values are never read from argv)")
	}
}

// ---- ara node add / remove ----

func cmdNodeAdd(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	fs := flag.NewFlagSet("node add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	id := fs.String("id", "", "node id")
	country := fs.String("country", "", "country code (RU, DE, NL, ...)")
	role := fs.String("role", "", "ru | foreign")
	prio := fs.Int("priority", 100, "failover priority (lower = preferred)")
	if err := fs.Parse(tail); err != nil {
		return emitUsageError(g, err)
	}
	if *id == "" || *country == "" || *role == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id, --country, --role are required"}, nil)
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	n, err := st.AddNode(*id, strings.ToUpper(*country), *role, *prio)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if g.json {
		return okJSON(g, map[string]any{"node": n})
	}
	fmt.Println(i18n.T(lang, "topology.node_added", map[string]any{"id": n.ID, "country": n.Country, "role": n.Role}))
	return schema.ExitOK
}

func cmdNodeRemove(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	fs := flag.NewFlagSet("node remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	id := fs.String("id", "", "node id")
	if err := fs.Parse(tail); err != nil {
		return emitUsageError(g, err)
	}
	if *id == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	if err := st.RevokeNode(*id); err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if g.json {
		return okJSON(g, map[string]any{"revoked": *id})
	}
	fmt.Println(i18n.T(lang, "topology.node_removed", map[string]any{"id": *id}))
	return schema.ExitOK
}

// ---- ara link list / add / set-profile / remove ----

func cmdLink(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara link list | link add --edge E --exit X [--transport tcp|udp] [--profile-id ID] [--priority N] | link set-profile --id L (--profile-id ID | --legacy) | link remove --id L")
		return schema.ExitUsage
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	switch tail[0] {
	case "list":
		links, err := st.ListLinks()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		profs, _ := st.ListTransportProfiles("")
		byID := map[string]*transportprofile.Profile{}
		for i := range profs {
			byID[profs[i].ID] = &profs[i]
		}
		type linkView struct {
			ID        string `json:"id"`
			EdgeID    string `json:"edge_id"`
			ExitID    string `json:"exit_id"`
			Transport string `json:"transport"`
			Priority  int    `json:"priority"`
			ProfileID string `json:"profile_id,omitempty"`
			Protocol  string `json:"protocol"`
		}
		out := []linkView{}
		for _, l := range links {
			v := linkView{ID: l.ID, EdgeID: l.EdgeID, ExitID: l.ExitID, Transport: l.Transport, Priority: l.Priority}
			if l.ProfileID != nil {
				v.ProfileID = *l.ProfileID
				if p, ok := byID[*l.ProfileID]; ok {
					v.Protocol = p.Description()
				}
			} else if l.Transport == "tcp" {
				v.Protocol = "legacy-vless-tls"
			} else {
				v.Protocol = "UNCONFIGURED (udp requires an explicit hysteria2 profile)"
			}
			out = append(out, v)
		}
		if g.json {
			return okJSON(g, map[string]any{"links": out})
		}
		fmt.Println(i18n.T(lang, "topology.links_title", map[string]any{"count": len(out)}))
		for _, v := range out {
			fmt.Printf("  %s  %s→%s  %s  %s  prio=%d\n", v.ID, v.EdgeID, v.ExitID, v.Transport, v.Protocol, v.Priority)
		}
		return schema.ExitOK

	case "add":
		fs := flag.NewFlagSet("link add", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		edge := fs.String("edge", "", "edge node id")
		exit := fs.String("exit", "", "exit node id")
		transport := fs.String("transport", "tcp", "network transport tcp|udp")
		profileID := fs.String("profile-id", "", "transport profile id (required for udp)")
		prio := fs.Int("priority", 100, "failover priority")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *edge == "" || *exit == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--edge and --exit are required"}, nil)
		}
		var pid *string
		if *profileID != "" {
			pid = profileID
		}
		l, err := st.AddLink(*edge, *exit, *transport, *prio, pid)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"link": l})
		}
		fmt.Println(i18n.T(lang, "topology.link_added", map[string]any{"id": l.ID, "edge": l.EdgeID, "exit": l.ExitID}))
		return schema.ExitOK

	case "set-profile":
		fs := flag.NewFlagSet("link set-profile", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "link id")
		profileID := fs.String("profile-id", "", "target transport profile id")
		legacy := fs.Bool("legacy", false, "restore the legacy tcp VLESS+TLS default (no profile)")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" || (*profileID == "" && !*legacy) {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id and (--profile-id | --legacy) are required"}, nil)
		}
		// plan → apply (reviewable protocol switch; rollback supported)
		target := ""
		if !*legacy {
			target = *profileID
		}
		planDoc, hash, err := svc.TransitPlanSetLinkProfile(*id, target, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if _, err := svc.TransitApply(planDoc.ID, hash); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		st2, err := svc.OpenControlStore()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		defer st2.Close()
		l, err := st2.GetLink(*id)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"link": l, "plan_id": planDoc.ID})
		}
		proto := "legacy-vless-tls"
		if l.ProfileID != nil {
			proto = *l.ProfileID
		}
		fmt.Println(i18n.T(lang, "topology.link_profile_set", map[string]any{"id": l.ID, "profile": proto}))
		return schema.ExitOK

	case "remove":
		fs := flag.NewFlagSet("link remove", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "link id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		if err := st.RevokeLink(*id); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"revoked": *id})
		}
		fmt.Println(i18n.T(lang, "topology.link_removed", map[string]any{"id": *id}))
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown link subcommand")
	return schema.ExitUsage
}

// ---- ara node transport capabilities | list | add-profile | revoke-profile | render ----

func cmdNodeTransport(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara node transport capabilities | list [--node N] | add-profile --node N --protocol vless|trojan|hysteria2 --server-name SNI --ca-path F [--alpn a,b] (--password-file F | --password-stdin) | revoke-profile --id ID | render --link L --endpoint host:port --socks-port P --server-cert F --server-key F --out DIR")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "capabilities":
		caps := service.TransitCapabilities()
		if g.json {
			return okJSON(g, caps)
		}
		fmt.Println(i18n.T(lang, "topology.caps_title", nil))
		for _, t := range caps["transit"].([]map[string]any) {
			fmt.Printf("  transit: %s/%s [%s]\n", t["protocol"], t["security"], t["status"])
		}
		for _, t := range caps["ingress"].([]map[string]any) {
			fmt.Printf("  ingress: %s/%s [%s]\n", t["protocol"], t["security"], t["status"])
		}
		for _, t := range caps["unsupported"].([]map[string]any) {
			fmt.Printf("  unsupported: %v — %v\n", t["protocol"], t["reason"])
		}
		return schema.ExitOK

	case "list":
		fs := flag.NewFlagSet("node transport list", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		node := fs.String("node", "", "filter by node id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		st, err := svc.OpenControlStore()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		defer st.Close()
		profs, err := st.ListTransportProfiles(*node)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		type profView struct {
			ID        string `json:"id"`
			NodeID    string `json:"node_id"`
			Protocol  string `json:"protocol"`
			Transport string `json:"transport"`
			Security  string `json:"security"`
			ServerName string `json:"server_name,omitempty"`
			Revoked   bool   `json:"revoked"`
		}
		out := []profView{}
		for _, p := range profs {
			v := profView{ID: p.ID, NodeID: p.NodeID, Protocol: string(p.Protocol), Transport: string(p.Transport), Security: string(p.Security), Revoked: p.RevokedAt != nil}
			if p.TLS != nil {
				v.ServerName = p.TLS.ServerName
			}
			out = append(out, v)
		}
		if g.json {
			return okJSON(g, map[string]any{"profiles": out})
		}
		if len(out) == 0 {
			fmt.Println(i18n.T(lang, "topology.profiles_empty", nil))
			return schema.ExitOK
		}
		for _, v := range out {
			state := ""
			if v.Revoked {
				state = " [revoked]"
			}
			fmt.Printf("  %s  %s  %s/%s  sni=%s%s\n", v.ID, v.NodeID, v.Protocol, v.Transport, v.ServerName, state)
		}
		return schema.ExitOK

	case "add-profile":
		fs := flag.NewFlagSet("node transport add-profile", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		node := fs.String("node", "", "exit node id")
		proto := fs.String("protocol", "", "vless | trojan | hysteria2")
		sni := fs.String("server-name", "", "TLS server_name the hop verifies")
		caPath := fs.String("ca-path", "", "pinned CA certificate path")
		alpn := fs.String("alpn", "", "comma-separated ALPN (optional)")
		pwFile := fs.String("password-file", "", "file with the credential value")
		pwStdin := fs.Bool("password-stdin", false, "read the credential value from stdin")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *node == "" || *proto == "" || *sni == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--node, --protocol and --server-name are required"}, nil)
		}
		secret, err := readSecret(*pwFile, *pwStdin)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		in := service.TransitProfileInput{NodeID: *node, Protocol: *proto, Security: "tls", Secret: secret}
		in.TLS.ServerName = *sni
		in.TLS.CAPath = *caPath
		if *alpn != "" {
			for _, a := range strings.Split(*alpn, ",") {
				if a = strings.TrimSpace(a); a != "" {
					in.TLS.ALPN = append(in.TLS.ALPN, a)
				}
			}
		}
		planDoc, hash, err := svc.TransitPlanAddProfile(in, time.Now().UTC())
		if err != nil {
			code := schema.CodeValidation
			if strings.Contains(err.Error(), "UNSUPPORTED_CAPABILITY") {
				code = schema.CodeUnsupported
			}
			return fail(g, lang, code, "error."+code, nil, err)
		}
		if _, err := svc.TransitApply(planDoc.ID, hash); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		st, err := svc.OpenControlStore()
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		defer st.Close()
		profs, _ := st.ListTransportProfiles(*node)
		created := profs[len(profs)-1]
		if g.json {
			return okJSON(g, map[string]any{"profile": created, "plan_id": planDoc.ID})
		}
		fmt.Println(i18n.T(lang, "topology.profile_added", map[string]any{"id": created.ID, "node": created.NodeID, "proto": created.Description()}))
		fmt.Println(i18n.T(lang, "topology.profile_secret_note", nil))
		return schema.ExitOK

	case "revoke-profile":
		fs := flag.NewFlagSet("node transport revoke-profile", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "transport profile id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		planDoc, hash, err := svc.TransitPlanRevokeProfile(*id, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if _, err := svc.TransitApply(planDoc.ID, hash); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"revoked": *id})
		}
		fmt.Println(i18n.T(lang, "topology.profile_revoked", map[string]any{"id": *id}))
		return schema.ExitOK

	case "render":
		fs := flag.NewFlagSet("node transport render", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		link := fs.String("link", "", "link id")
		endpoint := fs.String("endpoint", "", "exit endpoint host:port")
		socksHost := fs.String("socks-host", "127.0.0.1", "adapter SOCKS listen host on the edge host")
		socksPort := fs.Int("socks-port", 0, "adapter SOCKS listen port (1171+ by convention)")
		serverCert := fs.String("server-cert", "", "exit-side certificate PEM path")
		serverKey := fs.String("server-key", "", "exit-side key PEM path")
		outDir := fs.String("out", "", "write exitch-<link>.json and exitin-<link>.json (0600) into DIR instead of stdout")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *link == "" || *endpoint == "" || *socksPort == 0 || *serverCert == "" || *serverKey == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--link, --endpoint, --socks-port, --server-cert and --server-key are required"}, nil)
		}
		ep, err := transportprofile.ParseEndpoint(*endpoint)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		adapter, inbound, err := svc.TransitRender(*link, ep, *socksHost, *socksPort, *serverCert, *serverKey)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if *outDir == "" {
			if g.json {
				return okJSON(g, map[string]any{"adapter": adapter, "inbound": inbound})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			fmt.Println("// edge-side transit adapter (exitch): SOCKS loopback in → profile out")
			_ = enc.Encode(adapter)
			fmt.Println("// exit-side inbound (exitin): terminates the protocol")
			_ = enc.Encode(inbound)
			return schema.ExitOK
		}
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		for _, f := range []struct {
			name string
			cfg  map[string]any
		}{{"exitch-" + *link + ".json", adapter}, {"exitin-" + *link + ".json", inbound}} {
			b, err := json.MarshalIndent(f.cfg, "", "  ")
			if err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
			path := *outDir + "/" + f.name
			if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
				return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
			}
			fmt.Println(path)
		}
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown node transport subcommand")
	return schema.ExitUsage
}

// ---- ara topology plan | apply (declarative document) ----

func cmdTopology(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) < 1 || (tail[0] != "plan" && tail[0] != "apply") {
		fmt.Fprintln(os.Stderr, "usage: ara topology plan --file topology.json --output plan.json | topology apply --plan plan.json --expected-hash HASH")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "plan":
		fs := flag.NewFlagSet("topology plan", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		file := fs.String("file", "", "topology JSON document")
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
		var doc service.TopologyDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		planDoc, hash, err := svc.TopologyPlan(&doc, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := writePlanFile(*output, planDoc, hash); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan_id": planDoc.ID, "plan_hash": hash, "expires_at": planDoc.ExpiresAt})
		}
		fmt.Println(i18n.T(lang, "topology.plan_created", map[string]any{"id": planDoc.ID, "nodes": len(doc.Nodes), "profiles": len(doc.TransportProfiles), "links": len(doc.Links)}))
		fmt.Fprintf(os.Stderr, "plan_hash: %s\n", hash)
		return schema.ExitOK

	case "apply":
		fs := flag.NewFlagSet("topology apply", flag.ContinueOnError)
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
		res, err := svc.TopologyApply(planDoc.ID, *hash)
		if err != nil {
			return applyErrToExit(g, lang, err)
		}
		if g.json {
			return okJSON(g, res)
		}
		fmt.Println(i18n.T(lang, "topology.apply_ok", map[string]any{"changes": res.Summary["changes"]}))
		return schema.ExitOK
	}
	return schema.ExitUsage
}
