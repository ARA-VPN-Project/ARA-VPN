// ara speedtest: the CLI half of the path-speed diagnostics — equal to
// the UI, JSON envelopes, stable exit codes, explicit budgets, honest
// failures. Segments run sequentially; directions sequentially inside a
// job (docs/SPEEDTEST.md).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aravpn/core/schema"
	"aravpn/core/speedtest"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func cmdSpeedtest(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ara speedtest run --segment client-edge|edge-exit|e2e [--exit ID] [--endpoint host:port] [--token-file F | --token-stdin] [--direction down|up|both] [--budget quick|extended] [--rate-note TEXT] [--source LABEL] [--transit PROTO] | status --id | history [--limit N] | cancel --id | export --id [--redact-endpoints]")
		return schema.ExitUsage
	}
	switch tail[0] {
	case "run":
		return speedtestRun(svc, g, tail[1:], lang)
	case "status":
		fs := flag.NewFlagSet("speedtest status", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "job id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		j, err := svc.SpeedtestJobStatus(*id)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, j)
		}
		fmt.Printf("%s  %s  %s  %s\n", j.ID, j.Segment, j.Direction, j.Status)
		for _, r := range j.Results {
			printSpeedtestResult(lang, r)
		}
		if j.Error != "" {
			fmt.Println(i18n.T(lang, "speedtest.job_failed", map[string]any{"reason": j.Error}))
		}
		return schema.ExitOK
	case "history":
		fs := flag.NewFlagSet("speedtest history", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		limit := fs.Int("limit", 20, "max records")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		jobs, err := svc.SpeedtestHistory(*limit)
		if err != nil {
			return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"jobs": jobs})
		}
		for _, j := range jobs {
			line := fmt.Sprintf("%s  %s  %s  %s", j.CreatedAt.Format(time.RFC3339), j.ID, j.Segment+" "+j.Direction, j.Status)
			for _, r := range j.Results {
				if r.Metrics.OK {
					line += fmt.Sprintf("  %.1f/%.1f Mbit/s", r.Metrics.GoodputMbps, r.Metrics.GoodputMbps)
					break
				}
			}
			fmt.Println(line)
		}
		return schema.ExitOK
	case "cancel":
		fs := flag.NewFlagSet("speedtest cancel", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "job id")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		if err := svc.SpeedtestCancel(*id); err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"canceled": *id})
		}
		fmt.Println(i18n.T(lang, "speedtest.canceled", map[string]any{"id": *id}))
		return schema.ExitOK
	case "export":
		fs := flag.NewFlagSet("speedtest export", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		id := fs.String("id", "", "job id")
		redact := fs.Bool("redact-endpoints", false, "mask endpoint addresses in the report")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *id == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--id required"}, nil)
		}
		out, err := svc.SpeedtestExport(*id, *redact)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if g.json {
			return okJSON(g, out)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return schema.ExitOK
	}
	fmt.Fprintln(os.Stderr, "unknown speedtest subcommand")
	return schema.ExitUsage
}

func speedtestRun(svc *service.Service, g *globals, args []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("speedtest run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	segment := fs.String("segment", "client-edge", "client-edge | edge-exit | e2e | direct")
	exitID := fs.String("exit", "", "exit id (edge-exit/e2e labeling)")
	endpoint := fs.String("endpoint", "", "testpoint host:port AS DIALED")
	tokenFile := fs.String("token-file", "", "file with the endpoint bearer token")
	tokenStdin := fs.Bool("token-stdin", false, "read the bearer token from stdin")
	direction := fs.String("direction", "both", "down | up | both")
	budgetKey := fs.String("budget", "quick", "quick | extended")
	rateNote := fs.String("rate-note", "", "annotation of the applied limit (auto-filled from limits state when empty)")
	source := fs.String("source", "", "source label (default: this host)")
	transit := fs.String("transit", "", "transit protocol annotation, e.g. trojan+tls/tcp")
	if err := fs.Parse(args); err != nil {
		return emitUsageError(g, err)
	}
	if *endpoint == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--endpoint host:port is required (ARA never sends measurements to arbitrary URLs)"}, nil)
	}
	token, err := readSecret(*tokenFile, *tokenStdin)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	budget, ok := service.SpeedtestBudgetPresets[*budgetKey]
	if !ok {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "budget must be quick|extended"}, nil)
	}
	seg := speedtest.Segment(*segment)
	switch seg {
	case speedtest.SegClientEdge, speedtest.SegEdgeExit, speedtest.SegEndToEnd, speedtest.SegDirect:
	default:
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "unknown segment"}, nil)
	}
	if seg == speedtest.SegDirect {
		// explicit opt-in only; never mixed into the through-chain numbers
		fmt.Fprintln(os.Stderr, "note: direct client↔exit is an opt-in comparison; it does not bypass kill switch or policy and is reported separately")
	}
	// estimate BEFORE the start; the note goes out in both human and JSON
	est := budget.EstimateBytes()
	if !g.json {
		fmt.Println(i18n.T(lang, "speedtest.estimate", map[string]any{
			"mib": est / (1 << 20), "budget": *budgetKey,
		}))
	}
	if *rateNote == "" {
		*rateNote = svc.SpeedtestRateLimitNote()
	}
	src := *source
	if src == "" {
		host, _ := os.Hostname()
		src = "client@" + host
	}
	dest := *exitID
	if dest == "" {
		dest = strings.SplitN(*endpoint, ":", 2)[0]
	}

	// Ctrl-C cancels: generation stops, partial result is kept honestly
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	release, err := svc.SpeedtestAcquire("pending")
	if err != nil {
		return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
	}
	defer release()

	dirs := []speedtest.Direction{speedtest.DirDown, speedtest.DirUp}
	switch *direction {
	case "down":
		dirs = []speedtest.Direction{speedtest.DirDown}
	case "up":
		dirs = []speedtest.Direction{speedtest.DirUp}
	case "both":
	default:
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "direction must be down|up|both"}, nil)
	}

	jobOuts := []service.SpeedtestJob{}
	for i, dir := range dirs {
		if i > 0 {
			// sequential by design: segments/directions must stay comparable
			time.Sleep(500 * time.Millisecond)
		}
		spec := speedtest.Spec{
			Segment: seg, Source: src, Dest: dest, Endpoint: *endpoint,
			Token: token, Direction: dir, Budget: budget,
			TransitProtocol: *transit, RateLimitNote: *rateNote,
		}
		job, err := svc.SpeedtestRunJob(ctx, spec, *budgetKey, map[string]string{"exit_id": *exitID}, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		jobOuts = append(jobOuts, *job)
		if job.Status == "canceled" {
			break
		}
	}
	// chain the analysis across the history of comparable segments
	obs := speedtestObservations(svc)
	an := speedtest.Analyze(obs)
	jobOut := jobOuts[len(jobOuts)-1]
	jobOut.Analysis = &an
	if g.json {
		if len(jobOuts) == 1 {
			return okJSON(g, jobOut)
		}
		return okJSON(g, map[string]any{"jobs": jobOuts, "analysis": an})
	}
	printSpeedtestJob(lang, jobOut, jobOuts)
	if jobOut.Status == "failed" {
		return schema.ExitUnavailable
	}
	return schema.ExitOK
}

// speedtestObservations collects recent successful results for the
// analyzer (segments are compared, never merged).
func speedtestObservations(svc *service.Service) []speedtest.Observation {
	jobs, err := svc.SpeedtestHistory(12)
	if err != nil {
		return nil
	}
	var obs []speedtest.Observation
	for _, j := range jobs {
		for _, r := range j.Results {
			obs = append(obs, speedtest.Observation{
				Segment: r.Segment, Dest: r.Dest, Direction: r.Direction,
				GoodputMbps: r.Metrics.GoodputMbps, OK: r.Metrics.OK, Error: r.Metrics.Error,
				RTTP50IdleMs: r.Metrics.RTTP50IdleMs, RTTP95IdleMs: r.Metrics.RTTP95IdleMs,
				RTTP95LoadedMs: r.Metrics.RTTP95LoadedMs, FailedProbeRatio: r.Metrics.FailedProbeRatio,
				RateLimited: r.RateLimited, RateLimitNote: r.RateLimitNote,
			})
		}
	}
	return obs
}

func printSpeedtestJob(lang i18n.Lang, j service.SpeedtestJob, all []service.SpeedtestJob) {
	fmt.Println(i18n.T(lang, "speedtest.title", nil))
	for _, jj := range all {
		for _, r := range jj.Results {
			printSpeedtestResult(lang, r)
		}
	}
	if j.Analysis != nil {
		for _, c := range j.Analysis.Caveats {
			fmt.Println("  ~ " + c)
		}
		for _, h := range j.Analysis.Hypotheses {
			detail := h.DetailRU
			if lang == i18n.EN {
				detail = h.DetailEN
			}
			fmt.Printf("  ? [%s] %s (%s)\n", h.Confidence, detail, h.Cause)
		}
	}
}

func printSpeedtestResult(lang i18n.Lang, r speedtest.Result) {
	if !r.Metrics.OK {
		fmt.Println(i18n.T(lang, "speedtest.job_failed", map[string]any{"reason": r.Metrics.Error}))
		return
	}
	fmt.Println(i18n.T(lang, "speedtest.result_line", map[string]any{
		"segment":    r.Segment,
		"direction":  r.Direction,
		"mbps":       fmt.Sprintf("%.1f", r.Metrics.GoodputMbps),
		"rtt_p50":    fmt.Sprintf("%.1f", r.Metrics.RTTP50IdleMs),
		"rtt_p95":    fmt.Sprintf("%.1f", r.Metrics.RTTP95IdleMs),
		"probe_fail": fmt.Sprintf("%.1f", r.Metrics.FailedProbeRatio*100),
		"bytes_mib":  r.Metrics.Bytes / (1 << 20),
		"duration_s": fmt.Sprintf("%.1f", r.DurationS),
	}))
	if r.RateLimited {
		fmt.Println(i18n.T(lang, "speedtest.limited_note", map[string]any{"limit": r.RateLimitNote}))
	}
}
