package main

// netplan operator commands: `ara netplan inspect` exports the durable
// evidence for every non-terminal plan; `ara netplan resolve` applies a
// journaled operator decision (as-applied → rollback; as-not-applied →
// resume). Unknown ownership is never cleared by deletion or journal
// cleanup — only by these journaled confirmations.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
	"aravpn/netplan"
)

func cmdNetplan(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 0 || (tail[0] != "inspect" && tail[0] != "resolve") {
		fmt.Fprintln(os.Stderr, "usage: ara netplan inspect | ara netplan resolve --plan <id>  (typed ResolutionPlan JSON on stdin)")
		return schema.ExitUsage
	}
	st := service.StateDir{Root: g.stateDir}
	if st.Root == "" {
		def, err := service.DefaultStateDir()
		if err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		st = def
	}
	j, err := netplan.OpenStepJournal(st.Root)
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	switch tail[0] {
	case "inspect":
		insp, fps, err := netplan.Inspect(j)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			if insp == nil {
				insp = []netplan.Inspection{}
			}
			return okJSON(g, map[string]any{"pending": insp, "fingerprints": fps})
		}
		if len(insp) == 0 {
			fmt.Println(i18n.T(lang, "netplan.clean", nil))
			return schema.ExitOK
		}
		for i, in := range insp {
			fmt.Printf("%s [%s]\n  fingerprint: %s\n", in.PlanID, in.State, fps[i])
			for _, st := range in.Steps {
				fmt.Printf("  step %d: %s apply=%s undo=%s\n", st.Step, st.Kind, st.Status, st.Undo)
			}
		}
		return schema.ExitOK

	case "resolve":
		fs := flag.NewFlagSet("netplan resolve", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		plan := fs.String("plan", "", "pending plan id")
		decision := fs.String("decision", "", "applied | not_applied (per unknown outcome)")
		evidence := fs.String("evidence", "", "what the operator verified and how (journaled)")
		_ = decision
		_ = evidence
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *plan == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--plan required"}, nil)
		}
		// the resolve executor finishes the plan by undo or resume with
		// the real typed op table; the journal validates scope for every op
		// the full typed resolution plan arrives as JSON on stdin (plan id,
		// hash, fingerprint, per-outcome entries, actor, evidence)
		raw, rerr := io.ReadAll(os.Stdin)
		if rerr != nil || len(raw) == 0 {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "resolution plan JSON required on stdin (--plan selects the journal plan id)"}, nil)
		}
		var rp netplan.ResolutionPlan
		if jerr := json.Unmarshal(raw, &rp); jerr != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, jerr)
		}
		rp.PlanID = *plan
		state, err := netplan.ResolveOperator(j, netplan.CommandExecutor{}, rp)
		if err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan": *plan, "state": state})
		}
		fmt.Println(i18n.T(lang, "netplan.resolved", map[string]any{"plan": *plan, "state": state}))
		return schema.ExitOK
	}
	return schema.ExitUsage
}
