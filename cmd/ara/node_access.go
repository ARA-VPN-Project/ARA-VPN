package main

import (
	"aravpn/core/nodeaccess"
	"aravpn/core/policy"
	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func cmdNodeAccess(g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 1 && tail[0] == "serve" {
		if err := serveNodeAccess(); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		return schema.ExitOK
	}
	if len(tail) == 0 || (tail[0] != "plan" && tail[0] != "apply" && tail[0] != "remove") {
		return schema.ExitUsage
	}
	fs := flag.NewFlagSet("node access "+tail[0], flag.ContinueOnError)
	var in nodeaccess.Input
	fs.StringVar(&in.Kind, "kind", "ingress", "ingress | transit")
	fs.StringVar(&in.Protocol, "protocol", "tcp", "tcp | udp")
	fs.IntVar(&in.Port, "port", 0, "service port")
	fs.StringVar(&in.Interface, "interface", "", "receiving interface")
	fs.StringVar(&in.Source, "source", "", "allowed IP/CIDR (required for transit)")
	fs.StringVar(&in.Table, "table", "filter", "existing inet table")
	if err := fs.Parse(tail[1:]); err != nil {
		return emitUsageError(g, err)
	}
	plan, err := nodeaccess.Build(in)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if tail[0] != "plan" {
		if err := applyNodeAccess(plan, tail[0] == "remove"); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
	}
	if g.json {
		return okJSON(g, map[string]any{"operation": tail[0], "plan": plan})
	}
	if tail[0] == "plan" {
		fmt.Println(plan.Rule)
	} else {
		fmt.Println(i18n.T(lang, "node.access."+tail[0], nil))
	}
	return schema.ExitOK
}

func applyNodeAccess(plan nodeaccess.Plan, remove bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("nftables access change requires root")
	}
	const lockDir = "/run/ara-node-access"
	if err := os.MkdirAll(lockDir, 0755); err != nil {
		return err
	}
	unlock, err := policy.LockDir(lockDir)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run := func(input string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "nft", args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("nft: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return out, nil
	}
	data, err := run("", "-j", "-a", "list", "chain", "inet", plan.Table, nodeaccess.Chain)
	if err != nil {
		return err
	}
	var list struct {
		Entries []struct {
			Chain *struct{ Hook string } `json:"chain"`
			Rule  *struct {
				Handle  uint64 `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	var found bool
	var deletes strings.Builder
	for _, entry := range list.Entries {
		if entry.Chain != nil {
			if entry.Chain.Hook != "" {
				return fmt.Errorf("the ARA access chain must be a regular chain")
			}
			found = true
		}
		if entry.Rule != nil && entry.Rule.Comment == plan.Tag && entry.Rule.Handle != 0 {
			fmt.Fprintf(&deletes, "delete rule inet %s %s handle %d\n", plan.Table, nodeaccess.Chain, entry.Rule.Handle)
		}
	}
	if !found {
		return fmt.Errorf("the ARA access chain is missing")
	}
	if remove && deletes.Len() == 0 || !remove && deletes.Len() != 0 {
		return nil
	}
	batch := deletes.String()
	if !remove {
		batch = plan.Rule + "\n"
	}
	_, err = run(batch, "-f", "-")
	return err
}
