// Edge config auto-apply CLI + the EDGE-side sync (docs/FEDERATION.md):
// control side — plan/apply against the owning panel; edge side — signed
// pull of the dispatched config with a backup for rollback.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aravpn/core/fedauth"
	"aravpn/core/policy"
	"aravpn/core/schema"
	"aravpn/internal/edgeconfval"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

// ---- ara node edge-config plan | apply (on the owning panel) ----

func cmdNodeEdgeConfig(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(tail) < 1 || (tail[0] != "plan" && tail[0] != "apply") {
		fmt.Fprintln(os.Stderr, `usage: ara node edge-config plan --edge-node N --panel-id EDGE-PANEL --subscription SUB --owner-url URL --access-listen host:port --tls-cert F --tls-key F --ca-cert F [--state-dir D] [--status-file F] [--lease-bytes N] --output plan.json
       ara node edge-config apply --plan plan.json --expected-hash HASH`)
		return schema.ExitUsage
	}
	switch tail[0] {
	case "plan":
		fs := flag.NewFlagSet("node edge-config plan", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		in := service.EdgeConfigInput{}
		fs.StringVar(&in.EdgeNodeID, "edge-node", "", "edge node id in the topology")
		fs.StringVar(&in.EdgePanelID, "panel-id", "", "the edge's federation panel id")
		fs.StringVar(&in.Subscription, "subscription", "", "subscription id (devices come from its account)")
		fs.StringVar(&in.OwnerURL, "owner-url", "", "owner panel base URL for quota reports")
		fs.StringVar(&in.AccessListen, "access-listen", "", "vless access listener host:port")
		fs.StringVar(&in.SOCKSListen, "socks-listen", "", "optional SOCKS listener")
		fs.StringVar(&in.TLSCert, "tls-cert", "", "access TLS certificate")
		fs.StringVar(&in.TLSKey, "tls-key", "", "access TLS key")
		fs.StringVar(&in.CACert, "ca-cert", "", "pinned CA for transit hops")
		fs.StringVar(&in.ExitDNSAddr, "exit-dns-addr", "", "exit-scoped resolver host:port (REQUIRED: domain destinations resolve inside the exit scope)")
		fs.StringVar(&in.PolicyFile, "policy-file", "", "accepted policy document the Edge enforces")
		fs.StringVar(&in.StateDir, "edge-state-dir", "/var/lib/ara-edge", "state dir ON THE EDGE host")
		fs.StringVar(&in.StatusFile, "status-file", "", "status file ON THE EDGE host")
		fs.Int64Var(&in.LeaseBytes, "lease-bytes", 0, "lease size (default 1 MiB)")
		backbones := fs.String("backbones-file", "", "JSON map of exit ID to preconfigured OpenVPN/WireGuard SOCKS backbone")
		output := fs.String("output", "", "plan output file")
		if err := fs.Parse(tail[1:]); err != nil {
			return emitUsageError(g, err)
		}
		if *output == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--output required"}, nil)
		}
		if *backbones != "" {
			f, err := os.Open(*backbones)
			if err != nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
			}
			bounded := &io.LimitedReader{R: f, N: (64 << 10) + 1}
			dec := json.NewDecoder(bounded)
			dec.DisallowUnknownFields()
			err = dec.Decode(&in.ExitBackbones)
			if err == nil {
				var extra any
				if dec.Decode(&extra) != io.EOF {
					err = fmt.Errorf("backbones file must contain one JSON object")
				}
			}
			f.Close()
			if err != nil || bounded.N == 0 || in.ExitBackbones == nil {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "invalid backbone map"}, err)
			}
		}
		planDoc, hash, cfg, err := svc.EdgeConfigPlan(in, time.Now().UTC())
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if err := writePlanFile(*output, planDoc, hash); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"plan_id": planDoc.ID, "plan_hash": hash, "config": cfg})
		}
		fmt.Println(i18n.T(lang, "edgeconfig.plan_created", map[string]any{"id": planDoc.ID}))
		fmt.Fprintf(os.Stderr, "plan_hash: %s\n", hash)
		return schema.ExitOK

	case "apply":
		fs := flag.NewFlagSet("node edge-config apply", flag.ContinueOnError)
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
		res, err := svc.EdgeConfigApply(planDoc.ID, *hash)
		if err != nil {
			return applyErrToExit(g, lang, err)
		}
		if g.json {
			return okJSON(g, res)
		}
		fmt.Println(i18n.T(lang, "edgeconfig.applied", map[string]any{"path": res.Summary["path"]}))
		return schema.ExitOK
	}
	return schema.ExitUsage
}

// ---- ara edge sync (on the EDGE host: signed pull + local write) ----

func cmdEdgeSync(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	fs := flag.NewFlagSet("edge sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	base := fs.String("base", "", "owner panel base URL")
	force := fs.Bool("force", false, "write even when the hash is unchanged")
	// C06: the installed ara-edge unit reads /etc/ara-edge/edge.json —
	// sync can install the verified config there (root, 0640 root:ara-edge)
	// and reload the unit, closing the state-dir↔installed-service gap.
	installPath := fs.String("install-path", "", "also install the verified config to this path (e.g. /etc/ara-edge/edge.json)")
	reloadUnit := fs.String("reload-unit", "", "systemd unit to SIGHUP after install (e.g. ara-edge)")
	args := tail
	if len(args) > 0 && args[0] == "sync" {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return emitUsageError(g, err)
	}
	if *base == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--base required"}, nil)
	}
	ident := svc.PanelIdentity()
	if ident == nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "run `ara panel init --id EDGE-PANEL` in this state dir first"}, nil)
	}
	// D02/E02: the sync uses the FEDERATION transport contract — HTTPS
	// (loopback http allowed for lab), redirects REFUSED (a 302 must never
	// receive the owner's signature), bounded response size. The signature
	// signs OUR request; nothing is forwarded to another origin.
	baseURL := strings.TrimRight(*base, "/")
	if verr := service.ValidateFedBase(baseURL); verr != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, verr)
	}
	// signed GET (empty body)
	path := "/api/fed/v1/edge/config"
	ts := time.Now().Unix()
	nonce := "s-" + fmt.Sprint(time.Now().UnixNano())
	req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
	if err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	req.Header.Set("X-ARA-Panel", ident.PanelID)
	req.Header.Set("X-ARA-Timestamp", fmt.Sprint(ts))
	req.Header.Set("X-ARA-Nonce", nonce)
	req.Header.Set("X-ARA-Signature", ident.Sign(http.MethodGet, path, ts, nonce, nil))
	resp, err := (&http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Do(req)
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation,
			nil, fmt.Errorf("owner answered with a redirect (%s) — federation sync never follows it", loc))
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, 16<<20)
	var out struct {
		ConfigHash string `json:"config_hash"`
		ConfigRaw  string `json:"config_raw"`
		Error      string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ConfigRaw == "" {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, map[string]any{"detail": orStr(out.Error, fmt.Sprint(resp.StatusCode))}, nil)
	}
	dir := filepath.Join(svc.State.Root, "edge-config")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	activeHash := ""
	if b, err := os.ReadFile(filepath.Join(dir, "active.hash")); err == nil {
		activeHash = strings.TrimSpace(string(b))
	}
	target := filepath.Join(dir, "edge.json")
	if activeHash == out.ConfigHash && !*force && *installPath == "" {
		if g.json {
			return okJSON(g, map[string]any{"changed": false, "hash": out.ConfigHash, "path": target})
		}
		fmt.Println(i18n.T(lang, "edgeconfig.unchanged", map[string]any{"hash": out.ConfigHash[:12]}))
		return schema.ExitOK
	}
	// D02: the SIGNED hash must match the payload BEFORE anything is
	// staged — a hash/content divergence refuses the whole sync.
	sum := sha256.Sum256([]byte(out.ConfigRaw))
	if hex.EncodeToString(sum[:]) != out.ConfigHash {
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification,
			nil, fmt.Errorf("owner hash %s does not match the payload sha256 %s — refusing", out.ConfigHash, hex.EncodeToString(sum[:])))
	}
	// E02 #5: a matching hash does NOT prove usability — the config is
	// validated SEMANTICALLY before anything is written: it must parse as
	// an edge config object with devices/exits arrays.
	if verr := validateEdgeConfigShape([]byte(out.ConfigRaw)); verr != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, verr)
	}
	// E02: one transaction lock over staged→install→reload→health→commit.
	release, lerr := policy.LockDir(svc.State.Root)
	if lerr != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, fmt.Errorf("sync lock: %w", lerr))
	}
	defer release()
	// STAGED first: the verified bytes land next to the working copy with
	// the local hash re-checked before activation (D02).
	staged := target + ".staged"
	if err := atomicWriteFile(staged, []byte(out.ConfigRaw), 0o600); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	// E02: the staged checksum is computed over the ACTUAL staged bytes
	// (read back from disk), not over the in-memory payload
	stagedBytes, serr := os.ReadFile(staged)
	if serr != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, serr)
	}
	stagedSum := sha256.Sum256(stagedBytes)
	if hex.EncodeToString(stagedSum[:]) != out.ConfigHash {
		os.Remove(staged)
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification,
			nil, fmt.Errorf("staged copy hash mismatch — refusing activation"))
	}
	// backup the previous working copy for rollback
	if prev, err := os.ReadFile(target); err == nil {
		_ = atomicWriteFile(target+".bak", prev, 0o600)
	}
	if err := os.Rename(staged, target); err != nil {
		return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
	}
	if *installPath != "" {
		// D02: one transaction disk→installed→reload→health→commit.
		// active.hash is written LAST — a failed install leaves it stale,
		// so a retry re-installs the same verified plan instead of
		// returning "unchanged".
		instBackup := *installPath + ".bak"
		if prev, err := os.ReadFile(*installPath); err == nil {
			_ = atomicWriteFile(instBackup, prev, 0o640)
		}
		if err := installEdgeConfig(*installPath, []byte(out.ConfigRaw)); err != nil {
			// restore the previous installed bytes; the retry completes
			// the same plan (active.hash untouched)
			if prev, rerr := os.ReadFile(instBackup); rerr == nil {
				_ = installEdgeConfig(*installPath, prev)
			}
			return fail(g, lang, schema.CodePermission, schema.CodePermission, nil, err)
		}
		if *reloadUnit != "" {
			out2, rerr := exec.Command("systemctl", "kill", "-s", "HUP", *reloadUnit+".service").CombinedOutput()
			if rerr != nil {
				if prev, rerr := os.ReadFile(instBackup); rerr == nil {
					_ = installEdgeConfig(*installPath, prev)
					_ = exec.Command("systemctl", "kill", "-s", "HUP", *reloadUnit+".service").Run()
				}
				return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, fmt.Errorf("reload %s: %s; previous config restored", *reloadUnit, strings.TrimSpace(string(out2))))
			}
			stateDir := ""
			var cfgProbe struct {
				StateDir string `json:"state_dir"`
			}
			if json.Unmarshal([]byte(out.ConfigRaw), &cfgProbe) == nil {
				stateDir = cfgProbe.StateDir
			}
			if stateDir == "" {
				stateDir = filepath.Dir(*installPath)
			}
			// 2.2 PLANNED RESTART: the edge may answer RESTART_REQUIRED for
			// static serving changes (endpoints/topology/routes). The edge
			// keeps its previous state and does NOT update serving.hash;
			// after the grace window, if the receipt did not advance, the
			// sync restarts OUR OWN unit (never foreign services), waits
			// for the NEW process receipt, and continues to the commit.
			deadlineRestart := time.Now().Add(8 * time.Second)
			restartNeeded := false
			for time.Now().Before(deadlineRestart) {
				if sb, se := os.ReadFile(filepath.Join(stateDir, "serving.hash")); se == nil && strings.TrimSpace(string(sb)) == out.ConfigHash {
					break // hot reload accepted — no restart needed
				}
				time.Sleep(300 * time.Millisecond)
				if time.Now().After(deadlineRestart.Add(-100 * time.Millisecond)) {
					restartNeeded = true
				}
			}
			if restartNeeded {
				if rerr := exec.Command("systemctl", "restart", *reloadUnit+".service").Run(); rerr != nil {
					if prev, rerr := os.ReadFile(instBackup); rerr == nil {
						_ = installEdgeConfig(*installPath, prev)
						_ = exec.Command("systemctl", "restart", *reloadUnit+".service").Run()
					}
					return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil,
						fmt.Errorf("planned restart %s failed; previous config restored: %w", *reloadUnit, rerr))
				}
			}
			// health: the reloaded unit must be active AND must have
			// acknowledged the NEW config (G03): the edge writes the
			// sha256 of the config it actually loaded into
			// <state_dir>/serving.hash — is-active alone never proves
			// config adoption.
			if stateDir == "" {
				if prev, rerr := os.ReadFile(instBackup); rerr == nil {
					_ = installEdgeConfig(*installPath, prev)
					_ = exec.Command("systemctl", "kill", "-s", "HUP", *reloadUnit+".service").Run()
				}
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation,
					nil, fmt.Errorf("config has no state_dir — serving acknowledgment is impossible; previous config restored"))
			}
			// G03/I03/2.1: the serving acknowledgment is the ATOMIC receipt
			// bound to the CURRENT process instance — config hash, instance
			// nonce/pid, generation, accepted_at AFTER the apply started.
			// The legacy serving.hash hex is accepted ONLY when the receipt
			// is absent (old agent) — a deliberate capability policy, not a
			// silent downgrade: the unit must then have been restarted (new
			// MainPID) for the mtime-fresh hash to count.
			restartAt := time.Now()
			deadline := restartAt.Add(10 * time.Second)
			accepted := false
			receiptPath := filepath.Join(stateDir, "serving.receipt.json")
			servingHashPath := filepath.Join(stateDir, "serving.hash")
			for time.Now().Before(deadline) {
				if o, e := exec.Command("systemctl", "is-active", *reloadUnit+".service").Output(); e == nil && strings.TrimSpace(string(o)) == "active" {
					// current process identity from systemd (pid + start time)
					pidOut, _ := exec.Command("systemctl", "show", *reloadUnit+".service",
						"--property=MainPID", "--value").Output()
					curPID := strings.TrimSpace(string(pidOut))
					startOut, _ := exec.Command("systemctl", "show", *reloadUnit+".service",
						"--property=ExecMainStartTimestamp", "--value").Output()
					unitStart := strings.TrimSpace(string(startOut))
					okReceipt := false
					downgradeNote := ""
					if rb, re := os.ReadFile(receiptPath); re == nil {
						var rec struct {
							Instance     string `json:"instance"`
							ConfigSHA256 string `json:"config_sha256"`
							AcceptedAt   string `json:"accepted_at"`
						}
						if json.Unmarshal(rb, &rec) == nil && rec.ConfigSHA256 == out.ConfigHash {
							// instance binding: receipt nonce/pid must match
							// the CURRENT serving process (PID reuse guarded
							// by the unit start timestamp)
							pidMatches := curPID != "" && curPID != "0" && strings.Contains(rec.Instance, "pid"+curPID)
							at, perr := time.Parse(time.RFC3339Nano, rec.AcceptedAt)
							fresh := perr == nil && at.After(restartAt.Add(-time.Second))
							if pidMatches && fresh {
								okReceipt = true
							} else {
								downgradeNote = "receipt instance/generation stale"
							}
						} else {
							downgradeNote = "receipt unreadable"
						}
					}
					if !okReceipt {
						// legacy fallback (old agent without receipt): hex
						// hash + mtime fresh + unit restarted since apply
						if sb, sre := os.ReadFile(servingHashPath); sre == nil && strings.TrimSpace(string(sb)) == out.ConfigHash {
							if fi, fe := os.Stat(servingHashPath); fe == nil && fi.ModTime().After(restartAt.Add(-time.Second)) && unitStart != "" {
								okReceipt = true
								downgradeNote = "legacy serving.hash (old agent)"
							}
						}
					}
					if okReceipt {
						accepted = true
						if downgradeNote != "" {
							_ = downgradeNote // surfaced in the commit output below
						}
						break
					}
				}
				time.Sleep(300 * time.Millisecond)
			}
			if !accepted {
				if prev, rerr := os.ReadFile(instBackup); rerr == nil {
					_ = installEdgeConfig(*installPath, prev)
					_ = exec.Command("systemctl", "kill", "-s", "HUP", *reloadUnit+".service").Run()
				}
				return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable,
					nil, fmt.Errorf("health gate failed after reload — previous config restored; retry the sync"))
			}
		}
		// COMMIT: the verified plan is installed, reloaded and healthy —
		// only now the local active hash advances
		if err := atomicWriteFile(filepath.Join(dir, "active.hash"), []byte(out.ConfigHash+"\n"), 0o600); err != nil {
			return fail(g, lang, schema.CodeInternal, "error."+schema.CodeInternal, nil, err)
		}
	}
	if g.json {
		return okJSON(g, map[string]any{"changed": true, "hash": out.ConfigHash, "path": target,
			"installed": *installPath, "reloaded": *reloadUnit})
	}
	fmt.Println(i18n.T(lang, "edgeconfig.synced", map[string]any{"path": target}))
	if *installPath == "" {
		fmt.Fprintln(os.Stderr, "hint: pass --install-path /etc/ara-edge/edge.json --reload-unit ara-edge to apply to the installed service")
	}
	return schema.ExitOK
}

// validateEdgeConfigShape (E02/F02): the payload is validated by the
// SHARED typed validator (internal/edgeconfval) — the same identity/exit
// rules the runtime enforces. A matching sha256 or the presence of two
// arrays never proves usability.
func validateEdgeConfigShape(b []byte) error {
	return edgeconfval.Validate(b)
}

// installEdgeConfig atomically installs the verified config with the
// EXPLICIT ownership contract (D02): root:ara-edge 0640 — the group is
// resolved by NAME, so a fresh inode in root-owned /etc/ara-edge never
// silently becomes root:root.
func installEdgeConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".edge-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(tmp, 0, -1); err != nil {
			return err
		}
		// E02: the ownership contract is explicit — if the ara-edge group
		// does not exist, the install REFUSES instead of silently shipping
		// root:root where root:ara-edge is required.
		grp, gerr := user.LookupGroup("ara-edge")
		if gerr != nil {
			return fmt.Errorf("ownership contract: group ara-edge missing (create it or install the ara-edge package): %w", gerr)
		}
		gid, cerr := strconv.Atoi(grp.Gid)
		if cerr != nil {
			return fmt.Errorf("ownership contract: ara-edge gid invalid: %w", cerr)
		}
		if err := os.Chown(tmp, 0, gid); err != nil {
			return err
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		d.Close()
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var _ = io.Discard
var _ = fedauth.Skew
