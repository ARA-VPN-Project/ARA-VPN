package main

// update apply workflow (B42, C01/C02, D01): one install = ONE durable
// transaction over the journaled state machine.
//
// Transaction model (D01):
//   install-start (intent, artifact sha256)
//     → dpkg-install (known outcome) — a dpkg FAILURE after starting is a
//       PARTIAL effect: the transaction stays OPEN until recovery
//     → restart intents/outcomes
//     → health (known outcome)
//     → commit (terminal success; LKG promoted) — a journal write failure
//       here is NEVER reported as success
//   rollback: intent → dpkg (OLD bytes) → restart+health of the RESTORED
//     version → rollback-done (terminal ONLY when the restored version is
//     verified healthy); a failed rollback stays open (retryable via
//     recover)
//   recover: configure ARA-OWNED pending packages only (never foreign
//     pending packages) → restart → health → recover-done (terminal when
//     OK=true; OK=false stays open and can be retried)
//
// Fences: a torn/corrupt journal line refuses ALL mutations with a typed
// error (never skipped); an unclosed transaction refuses a new install;
// a durability failure anywhere is an error, never success. LKG is kept
// per component (updates/<component>/previous.deb) with the legacy shared
// path as fallback; the ACTUAL dpkg install uses the verified local
// candidate copy, never the operator's temp path. atomicWriteFile fsyncs
// file AND directory.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/policy"
	"aravpn/internal/service"
	"aravpn/internal/txlog"
)

type updateJournalEntry struct {
	At       time.Time `json:"at"`
	Step     string    `json:"step"` // install-start|dpkg-install|restart|health|commit|install-fail|rollback|rollback-done|recover-*
	Detail   string    `json:"detail,omitempty"`
	Identity string    `json:"identity,omitempty"` // sha256 of the artifact this step concerns
	OK       bool      `json:"ok"`
	// Outcome: known-ok | known-fail | unknown (the command's result could
	// not be observed — the process died mid-command).
	Outcome string `json:"outcome,omitempty"`
	// Component (D01): which ARA package this transaction installs; LKG is
	// tracked per component.
	Component string `json:"component,omitempty"`
	// Effect (E01): install-fail classification is TYPED — true = dpkg
	// started and the system may be partially changed (fenced until
	// recovery); false = refused before any effect (terminal); ABSENT =
	// unknown (legacy record — fenced, never reinterpreted as no-effect).
	Effect *bool `json:"effect,omitempty"`
	// V is the journal record version; 0/1 accepted, anything else is
	// unreadable by this build (fences, never skipped).
	V int `json:"v,omitempty"`
	// Parts (F04/G02): the per-component manifest of a BUNDLE transaction
	// — each part binds component → verified artifact sha256. Recovery
	// promotes exactly these parts, never other bytes.
	Parts []JournalPart `json:"parts,omitempty"`
}

// JournalPart binds one component of a bundle transaction to its verified
// artifact identity.
type JournalPart struct {
	Component string `json:"component"`
	Identity  string `json:"identity"`
}

// updateRunner is injectable for tests (fake dpkg/systemctl on PATH).
type updateRunner func(name string, args ...string) (string, error)

func realRunner(name string, args ...string) (string, error) {
	if name == "dpkg" && len(args) > 0 && args[0] == "--install" {
		args = append([]string{"--force-confold"}, args...)
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func updateJournalPath(svc *service.Service) string {
	return filepath.Join(svc.State.Root, "updates", "install-journal.jsonl")
}

func openUpdateJournal(svc *service.Service) (*txlog.Log, error) {
	if err := os.MkdirAll(filepath.Join(svc.State.Root, "updates"), 0o700); err != nil {
		return nil, err
	}
	return txlog.Open(updateJournalPath(svc))
}

const updateRollbackName = "previous.deb"

// araComponents are the ARA-owned packages: recovery configures ONLY these,
// never foreign pending packages (D01).
var araComponents = []string{"ara", "ara-edge", "ara-engine", "ara-control"}

// componentOfArtifact derives the ARA component from the artifact filename
// (ara-edge_1.2_amd64.deb → ara-edge); unknown shapes return "".
func componentOfArtifact(path string) string {
	base := filepath.Base(path)
	for _, c := range araComponents {
		if strings.HasPrefix(base, c+"_") {
			return c
		}
	}
	return ""
}

// lkgPath returns the per-component last-known-good path (D01); when the
// component is unknown the legacy shared path is used.
func lkgPath(svc *service.Service, component string) string {
	if component == "" {
		return filepath.Join(svc.State.Root, "updates", updateRollbackName)
	}
	return filepath.Join(svc.State.Root, "updates", component, updateRollbackName)
}

// lkgCandidates lists the retained LKG slots for this component: the
// per-component path first; the legacy shared path is a candidate ONLY
// when its compatibility with the component is PROVEN at selection time
// (E01 #4: dpkg-deb --field Package must name the same component, or the
// artifact has no known component). Foreign bytes are never installed.
func lkgCandidates(svc *service.Service, component string, run updateRunner) []string {
	paths := []string{}
	if component != "" {
		paths = append(paths, filepath.Join(svc.State.Root, "updates", component, updateRollbackName))
	}
	paths = append(paths, filepath.Join(svc.State.Root, "updates", updateRollbackName))
	return paths
}

// lkgCompatible proves the candidate LKG belongs to the component before
// its bytes are installed: for a KNOWN component the .deb Package field
// must match; with no known component any retained package is acceptable.
func lkgCompatible(svc *service.Service, run updateRunner, path, component string) bool {
	if component == "" {
		return true
	}
	out, err := run("dpkg-deb", "--field", path, "Package")
	if err != nil {
		return false // cannot prove compatibility — do not install
	}
	return strings.TrimSpace(out) == component
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// journalAppend is fail-closed (C02/D01): a durable-journal write failure
// returns an error and the caller must not report success.
func journalAppend(j *txlog.Log, e updateJournalEntry) error {
	if j == nil {
		return fmt.Errorf("INTERNAL: install journal unavailable")
	}
	return j.Append(e)
}

// journalReplay is the durable read side of the state machine (F01):
// the open transaction is BOUND to its component+artifact, and the actual
// PHASE (install vs rollback in flight) is reconstructed from every
// binding record — recovery acts on the real phase, not on the
// install-start line alone.
type journalReplay struct {
	Corrupt bool                // torn/corrupt/foreign-version record (fences everything)
	Open    *updateJournalEntry // unclosed install-start
	// Phase: "install" while the new artifact is being applied; "rollback"
	// from the first rollback intent until rollback-done. PhaseArtifact is
	// the sha256 the CURRENT phase is installing/restoring.
	Phase         string
	PhaseArtifact string
	// InstallStarted (H02): a dpkg-install record exists for the open
	// transaction — dpkg actually STARTED. Its absence means the crash
	// happened BEFORE dpkg ran: the candidate is not installed, and no
	// configure/restart result can prove anything about it.
	InstallStarted bool
	// InstallSucceeded (I01): a dpkg-install record with OK=true exists —
	// the candidate was successfully installed. A failed attempt (OK=false
	// Effect=true) does NOT prove installation and must be retried.
	InstallSucceeded bool
	// RestoreExecuted (I01): during the rollback phase a dpkg-install
	// with the PHASE artifact identity was recorded — the restore actually
	// ran. Its absence means the rollback intent never executed.
	RestoreExecuted bool
}

// binding reports whether a record belongs to the OPEN transaction's
// component (F01 #2): the transaction is bound to its COMPONENT, so a
// terminal record of another component never closes it. Identity inside
// the transaction legitimately changes between phases (a rollback
// restores the PREVIOUS artifact's identity), so identity equality is
// not a binding condition — the phase machine tracks which artifact the
// current phase installs/restores.
func binding(rec, open *updateJournalEntry) bool {
	if open == nil {
		return false
	}
	return rec.Component == open.Component
}

// replayJournal is the TYPED, VALIDATED read side of the state machine
// (D01/E01/F01): the whole JSONL must be intact (every line parses, the
// last line ends with a newline, versions are known); terminal
// transitions depend on the recorded OUTCOME, are BOUND to the open
// transaction (component+artifact), and never close another operation.
// A legacy install-fail without the Effect field is UNKNOWN — fenced,
// never reinterpreted as no-effect.
func replayJournal(svc *service.Service) (*journalReplay, error) {
	b, err := os.ReadFile(updateJournalPath(svc))
	if os.IsNotExist(err) {
		return &journalReplay{Phase: "install"}, nil
	}
	if err != nil {
		return nil, err
	}
	r := &journalReplay{Phase: "install"}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		// a final record without its newline is a torn write
		r.Corrupt = true
		r.Open = &updateJournalEntry{Step: "corrupt", Detail: "torn final record"}
		return r, nil
	}
	for i, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e updateJournalEntry
		if jsonErr := json.Unmarshal([]byte(line), &jsonErrHolder{E: &e}); jsonErr != nil || e.Step == "" {
			// a torn/foreign record means the process died mid-write: the
			// log is no longer interpretable — fence everything
			r.Corrupt = true
			r.Open = &updateJournalEntry{Step: "corrupt", Detail: fmt.Sprintf("line %d", i+1)}
			return r, nil
		}
		if e.V != 0 && e.V != 1 {
			r.Corrupt = true
			r.Open = &updateJournalEntry{Step: "corrupt", Detail: fmt.Sprintf("line %d: unknown journal version %d", i+1, e.V)}
			return r, nil
		}
		switch e.Step {
		case "install-start":
			if r.Open != nil {
				// a second start inside one open transaction is corrupt
				r.Corrupt = true
				r.Open = &updateJournalEntry{Step: "corrupt", Detail: fmt.Sprintf("line %d: nested install-start", i+1)}
				return r, nil
			}
			r.Open = &e
			r.Phase = "install"
			r.PhaseArtifact = e.Identity
		case "dpkg-install", "health", "restart":
			if !binding(&e, r.Open) {
				continue // foreign component: never advances this transaction
			}
			if e.Step == "dpkg-install" {
				r.InstallStarted = true
				if r.Phase == "rollback" && e.Identity == r.PhaseArtifact {
					r.RestoreExecuted = true
				}
				if e.OK {
					r.InstallSucceeded = true
					r.PhaseArtifact = e.Identity
				}
			}
		case "rollback":
			if !binding(&e, r.Open) {
				continue
			}
			// a rollback intent starts (or continues) the rollback phase:
			// the artifact being restored is the phase artifact. The
			// identity LEGITIMATELY changes here (OLD, not the candidate)
			// — the phase machine tracks the restored artifact.
			r.Phase = "rollback"
			r.PhaseArtifact = e.Identity
		case "commit":
			// terminal ONLY when successful AND bound to the INSTALL phase
			// artifact: a same-component commit of a DIFFERENT artifact
			// never closes this transaction (F/G02)
			if e.OK && binding(&e, r.Open) && e.Identity == r.Open.Identity {
				r.Open = nil
				r.Phase = "install"
			}
		case "rollback-done":
			// terminal ONLY after a recorded rollback intent, restoring the
			// artifact that intent named (F/G02: correct rollback artifact)
			if e.OK && binding(&e, r.Open) && r.Phase == "rollback" && e.Identity == r.PhaseArtifact {
				r.Open = nil
				r.Phase = "install"
			}
		case "abort":
			if e.OK && binding(&e, r.Open) && e.Identity == r.Open.Identity {
				r.Open = nil
				r.Phase = "install"
			}
		case "recover-done":
			// terminal ONLY when successful, bound by component, and the
			// identity is one the transaction actually applied (the
			// candidate or the restored artifact)
			if e.OK && binding(&e, r.Open) && (e.Identity == r.Open.Identity || (r.Phase == "rollback" && e.Identity == r.PhaseArtifact)) {
				r.Open = nil
				r.Phase = "install"
			}
		case "install-fail":
			// Effect: nil = legacy UNKNOWN (fenced, F01 #1); false = typed
			// no-effect (terminal); true = partial effect (fenced)
			if !binding(&e, r.Open) {
				continue
			}
			if e.Effect != nil && !*e.Effect {
				r.Open = nil
				r.Phase = "install"
			}
		}
		// "rollback-fail" never closes: a failed rollback stays fenced
		// until recovery (E01 requirement).
	}
	return r, nil
}

// jsonErrHolder lets the decoder surface JSON syntax errors while filling
// the typed entry.
type jsonErrHolder struct{ E *updateJournalEntry }

func (h jsonErrHolder) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, h.E) }

// updateRecoverWorkflow completes an INTERRUPTED install (C02/D01/F01):
// PHASE-AWARE — the actual phase is reconstructed from the whole open
// transaction. Rollback in flight: the restored artifact is the phase
// artifact (the retained LKG); its bytes are verified against the phase
// identity, health is gated, and NO candidate promotion happens — the LKG
// keeps the bytes that are actually installed. Install in flight: the
// verified candidate is promoted only when its sha256 matches the
// transaction identity. configure is scoped to the AFFECTED component;
// a failed recovery stays open (retryable).
func updateRecoverWorkflow(svc *service.Service, run updateRunner) (string, error) {
	if run == nil {
		run = realRunner
		if os.Geteuid() != 0 {
			return "", fmt.Errorf("PERMISSION_DENIED: package recovery requires root: run `sudo ara update recover`")
		}
	}
	release, err := policy.LockDir(svc.State.Root)
	if err != nil {
		return "", fmt.Errorf("update lock: %w", err)
	}
	defer release()
	j, err := openUpdateJournal(svc)
	if err != nil {
		return "", fmt.Errorf("install journal unavailable — refusing mutation: %w", err)
	}
	rep, err := replayJournal(svc)
	if err != nil {
		return "", err
	}
	if rep.Corrupt {
		return "", fmt.Errorf("JOURNAL_CORRUPT: install journal has torn records — inspect %s before any mutation", updateJournalPath(svc))
	}
	if rep.Open == nil {
		return "", fmt.Errorf("VALIDATION_FAILED: no interrupted install to recover")
	}
	open := *rep.Open
	if err := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-intent",
		Detail: open.Identity + " phase=" + rep.Phase, Identity: open.Identity, OK: true, Outcome: "known-ok", Component: open.Component, V: 1}); err != nil {
		return "", fmt.Errorf("journal write failed — refusing mutation: %w", err)
	}
	// I01: PHASE EXECUTION — complete the recorded action with explicit
	// attempt intent/result pairs. One operation = one begin (install-start);
	// each dpkg run is an attempt journaled as intent + result. Unknown or
	// failed results stay pending (retryable) — never reinterpreted.
	restoredIdentity := open.Identity
	switch rep.Phase {
	case "rollback":
		// restore the phase artifact: verify the retained archive matches
		// the recorded rollback identity, install when not yet executed
		lkg := lkgPath(svc, open.Component)
		data, rerr := os.ReadFile(lkg)
		if rerr != nil {
			journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "retained LKG unreadable: " + rerr.Error(), Identity: rep.PhaseArtifact, OK: false, Outcome: "known-fail", Component: open.Component, V: 1})
			return "", fmt.Errorf("RECOVER_INCOMPLETE: retained LKG unreadable: %w", rerr)
		}
		lid := fmt.Sprintf("%x", sha256.Sum256(data))
		if lid != rep.PhaseArtifact {
			journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "retained LKG does not match the recorded rollback artifact", Identity: rep.PhaseArtifact, OK: false, Outcome: "known-fail", Component: open.Component, V: 1})
			return "", fmt.Errorf("RECOVER_INCOMPLETE: retained LKG sha256 %s does not match the recorded rollback artifact %s — refusing to install unproven bytes; inspect %s", lid, rep.PhaseArtifact, lkg)
		}
		restoredIdentity = rep.PhaseArtifact
		if !rep.RestoreExecuted {
			if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install-intent", Detail: "restore " + rep.PhaseArtifact, Identity: rep.PhaseArtifact, OK: true, Outcome: "known-ok", Component: open.Component, V: 1}); aerr != nil {
				return "", fmt.Errorf("journal write failed — refusing mutation: %w", aerr)
			}
			iout, ierr := run("dpkg", "--install", lkg)
			step := updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: iout, Identity: rep.PhaseArtifact, OK: ierr == nil, Outcome: "known-ok", Component: open.Component, V: 1}
			if ierr != nil {
				step.Outcome = "known-fail"
				step.Effect = effectBool(true)
			}
			if aerr := journalAppend(j, step); aerr != nil {
				return "", fmt.Errorf("journal write failed after dpkg — state is open: %w", aerr)
			}
			if ierr != nil {
				return "", fmt.Errorf("RECOVER_FAILED: rollback install failed: %s", strings.TrimSpace(iout))
			}
		}
	default:
		// install phase: complete/verify the install when no SUCCESSFUL
		// dpkg result is recorded (none = unknown intent, failed = retry).
		// A recorded successful install means the candidate is already on
		// the system — skip the retry.
		if !rep.InstallStarted || !installResultOK(rep) {
			var candPaths []string
			if len(open.Parts) > 0 {
				for _, part := range open.Parts {
					cand := filepath.Join(svc.State.Root, "updates", "candidate-"+part.Component+".deb")
					id, verr := fileSHA256(cand)
					if verr != nil || id != part.Identity {
						journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "bundle candidate missing/mismatched for " + part.Component, Identity: open.Identity, OK: false, Outcome: "known-fail", Component: open.Component, Parts: open.Parts, V: 1})
						return "", fmt.Errorf("RECOVER_INCOMPLETE: bundle candidate for %s missing or does not match the recorded artifact — pending; inspect %s", part.Component, cand)
					}
					candPaths = append(candPaths, cand)
				}
			} else {
				candPath := filepath.Join(svc.State.Root, "updates", "candidate.deb")
				id, verr := fileSHA256(candPath)
				if verr == nil && id == open.Identity {
					candPaths = append(candPaths, candPath)
				} else if verr != nil {
					journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-configure", Detail: "no verified candidate — old version remains", Identity: open.Identity, OK: true, Outcome: "known-ok", Component: open.Component, V: 1})
				}
			}
			if len(candPaths) > 0 {
				if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install-intent", Detail: "retry verified install", Identity: open.Identity, OK: true, Outcome: "known-ok", Component: open.Component, V: 1}); aerr != nil {
					return "", fmt.Errorf("journal write failed — refusing mutation: %w", aerr)
				}
				installArgs := append([]string{"--install"}, candPaths...)
				iout, ierr := run("dpkg", installArgs...)
				step := updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: iout, Identity: open.Identity, OK: ierr == nil, Outcome: "known-ok", Component: open.Component, Parts: open.Parts, V: 1}
				if ierr != nil {
					step.Outcome = "known-fail"
					step.Effect = effectBool(true)
				}
				if aerr := journalAppend(j, step); aerr != nil {
					return "", fmt.Errorf("journal write failed after dpkg — state is open: %w", aerr)
				}
				if ierr != nil {
					return "", fmt.Errorf("RECOVER_FAILED: interrupted install retry failed: %s", strings.TrimSpace(iout))
				}
			}
		}
	}
	// configure the AFFECTED component(s): bundle carries its whole set;
	// legacy journals without component tracking fall back to the ARA set
	// (never foreign pending packages)
	targets := []string{open.Component}
	switch {
	case strings.HasPrefix(open.Component, "bundle:"):
		targets = strings.Split(strings.TrimPrefix(open.Component, "bundle:"), ",")
	case open.Component == "":
		targets = araComponents
	}
	args := append([]string{"--configure"}, targets...)
	out, cerr := run("dpkg", args...)
	if cerr != nil {
		journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-configure", Detail: out, Identity: open.Identity, OK: false, Outcome: "known-fail", Component: open.Component, V: 1})
		return "", fmt.Errorf("RECOVER_FAILED: dpkg configure %s: %s", strings.Join(targets, ","), strings.TrimSpace(out))
	}
	failed := restartARAServices(svc, j, run)
	ok := len(failed) == 0
	// PROMOTION: LKG must reflect the bytes actually installed and
	// health-verified. Install phase: promote the candidate(s) by their
	// recorded identities. Rollback phase: the retained LKG IS the
	// restored artifact — already correct, re-verified above.
	if ok && rep.Phase == "install" {
		if len(open.Parts) > 0 {
			for _, part := range open.Parts {
				cand := filepath.Join(svc.State.Root, "updates", "candidate-"+part.Component+".deb")
				id, verr := fileSHA256(cand)
				if verr != nil || id != part.Identity {
					journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "bundle candidate missing/mismatched for " + part.Component + " at promotion", Identity: open.Identity, OK: false, Outcome: "known-fail", Component: open.Component, Parts: open.Parts, V: 1})
					return "", fmt.Errorf("RECOVER_INCOMPLETE: bundle candidate for %s missing/mismatched at promotion — pending", part.Component)
				}
				if perr := promoteLKG(svc, part.Component, cand); perr != nil {
					journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "LKG promotion failed for " + part.Component + ": " + perr.Error(), Identity: open.Identity, OK: false, Outcome: "known-fail", Component: open.Component, Parts: open.Parts, V: 1})
					return "", fmt.Errorf("RECOVER_INCOMPLETE: LKG promotion %s: %w", part.Component, perr)
				}
			}
		} else {
			candCopy := filepath.Join(svc.State.Root, "updates", "candidate.deb")
			if id, verr := fileSHA256(candCopy); verr == nil && id == open.Identity {
				if perr := promoteLKG(svc, open.Component, candCopy); perr != nil {
					journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done", Detail: "LKG promotion failed: " + perr.Error(), Identity: open.Identity, OK: false, Outcome: "known-fail", Component: open.Component, V: 1})
					return "", fmt.Errorf("RECOVER_INCOMPLETE: LKG promotion failed: %w", perr)
				}
			}
		}
	}
	outcome := "known-ok"
	if !ok {
		outcome = "known-fail"
	}
	doneIdentity := open.Identity
	if rep.Phase == "rollback" {
		doneIdentity = restoredIdentity
	}
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "recover-done",
		Detail: fmt.Sprintf("phase=%s units failed: %s", rep.Phase, strings.Join(failed, ",")), Identity: doneIdentity, OK: ok, Outcome: outcome, Component: open.Component, Parts: open.Parts, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed after recovery — state is open: %w", aerr)
	}
	if !ok {
		// retryable: recover-done(OK=false) is NOT terminal
		return "", fmt.Errorf("RECOVER_INCOMPLETE: units %s still unhealthy — fix and re-run `ara update recover`", strings.Join(failed, ","))
	}
	return fmt.Sprintf("recovered (phase=%s, %s)", rep.Phase, strings.Join(targets, ",")), nil
}

// updateApplyBundle installs a DEPENDENT SET of staged packages (F04:
// engine+ara+edge 1→2) as ONE durable transaction: all artifacts are
// verified into candidate slots, ONE dpkg call installs them together
// (dpkg resolves the declared Depends ordering), one health gate covers
// the set, and the LKG of EVERY component is promoted only after the
// commit. The journal binds the transaction to the whole component set;
// recovery configures exactly that set.
func updateApplyBundle(svc *service.Service, artifacts []string, run updateRunner) (string, error) {
	if run == nil {
		run = realRunner
		if os.Geteuid() != 0 {
			return "", fmt.Errorf("PERMISSION_DENIED: package install requires root: run `sudo ara update apply --install --artifact <deb>[,<deb>…]`")
		}
	}
	if len(artifacts) == 0 {
		return "", fmt.Errorf("VALIDATION_FAILED: no artifacts")
	}
	if len(artifacts) == 1 {
		return updateApplyWorkflow(svc, artifacts[0], run)
	}
	release, err := policy.LockDir(svc.State.Root)
	if err != nil {
		return "", fmt.Errorf("update lock: %w", err)
	}
	defer release()
	j, err := openUpdateJournal(svc)
	if err != nil {
		return "", fmt.Errorf("install journal unavailable — refusing mutation: %w", err)
	}
	rep, err := replayJournal(svc)
	if err != nil {
		return "", err
	}
	if rep.Corrupt {
		return "", fmt.Errorf("JOURNAL_CORRUPT: install journal has torn records — run `ara update recover` after inspecting %s", updateJournalPath(svc))
	}
	if rep.Open != nil {
		return "", fmt.Errorf("INSTALL_INTERRUPTED: a previous install never completed — run `ara update recover` first")
	}
	updateDir := filepath.Join(svc.State.Root, "updates")
	type bundlePart struct {
		component string
		candCopy  string
		identity  string
	}
	var parts []bundlePart
	combined := ""
	for _, a := range artifacts {
		abs, aerr := filepath.Abs(a)
		if aerr != nil || !strings.HasSuffix(abs, ".deb") {
			return "", fmt.Errorf("VALIDATION_FAILED: --artifact must be .deb paths: %q", a)
		}
		if _, serr := os.Stat(abs); serr != nil {
			return "", fmt.Errorf("VALIDATION_FAILED: staged artifact unreadable: %w", serr)
		}
		comp := componentOfArtifact(abs)
		if comp == "" {
			return "", fmt.Errorf("VALIDATION_FAILED: bundle artifact %s has no recognizable ARA component name", filepath.Base(abs))
		}
		id, ierr := fileSHA256(abs)
		if ierr != nil {
			return "", ierr
		}
		candCopy := filepath.Join(updateDir, "candidate-"+comp+".deb")
		if data, rerr := os.ReadFile(abs); rerr != nil {
			return "", rerr
		} else if werr := atomicWriteFile(candCopy, data, 0o600); werr != nil {
			return "", werr
		}
		parts = append(parts, bundlePart{component: comp, candCopy: candCopy, identity: id})
		combined += id
	}
	combinedID := fmt.Sprintf("%x", sha256.Sum256([]byte(combined)))
	compList := make([]string, 0, len(parts))
	for _, p := range parts {
		compList = append(compList, p.component)
	}
	component := "bundle:" + strings.Join(compList, ",")
	jparts := make([]JournalPart, 0, len(parts))
	for _, p := range parts {
		jparts = append(jparts, JournalPart{Component: p.component, Identity: p.identity})
	}
	if err := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "install-start",
		Detail: strings.Join(artifacts, ","), Identity: combinedID, OK: true, Outcome: "known-ok", Component: component, Parts: jparts, V: 1}); err != nil {
		return "", fmt.Errorf("journal write failed — refusing mutation: %w", err)
	}
	installArgs := append([]string{"--install"}, func() []string {
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			out = append(out, p.candCopy)
		}
		return out
	}()...)
	out, derr := run("dpkg", installArgs...)
	if derr != nil {
		if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: out, Identity: combinedID, OK: false, Outcome: "known-fail", Component: component, Effect: effectBool(true), V: 1}); aerr != nil {
			return "", fmt.Errorf("journal write failed after dpkg failure: %w", aerr)
		}
		return "", fmt.Errorf("INSTALL_FAILED: %s; run `ara update recover` before the next install", strings.TrimSpace(out))
	}
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: out, Identity: combinedID, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed after dpkg — run `ara update recover`: %w", aerr)
	}
	failed := restartARAServices(svc, j, run)
	if len(failed) > 0 {
		if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "health", Detail: "units not active: " + strings.Join(failed, ","), Identity: combinedID, OK: false, Outcome: "known-fail", Component: component, V: 1}); aerr != nil {
			return "", fmt.Errorf("journal write failed after health failure: %w", aerr)
		}
		return "", fmt.Errorf("HEALTH_FAILED: units %s — the bundle transaction stays open; run `ara update recover`", strings.Join(failed, ","))
	}
	// commit: promote EVERY component's verified copy
	for _, p := range parts {
		if perr := promoteLKG(svc, p.component, p.candCopy); perr != nil {
			journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "commit", Detail: "LKG promotion failed for " + p.component + ": " + perr.Error(), Identity: combinedID, OK: false, Outcome: "known-fail", Component: component, V: 1})
			return "", fmt.Errorf("COMMIT_FAILED: LKG promotion %s: %w", p.component, perr)
		}
	}
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "commit", Detail: "health ok; LKG promoted for " + strings.Join(compList, ","), Identity: combinedID, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("COMMIT_FAILED: install succeeded but the durable commit could not be recorded — run `ara update recover`: %w", aerr)
	}
	return out, nil
}

// updateApplyWorkflow installs the staged package and verifies health.
func updateApplyWorkflow(svc *service.Service, stagedPath string, run updateRunner) (string, error) {
	if run == nil {
		run = realRunner
		// the root gate applies to the REAL runner only: injected runners
		// (tests, dry environments) verify the workflow without privileges
		if os.Geteuid() != 0 {
			return "", fmt.Errorf("PERMISSION_DENIED: package install requires root: run `sudo ara update apply --install --artifact %s`", stagedPath)
		}
	}
	abs, err := filepath.Abs(stagedPath)
	if err != nil || !strings.HasSuffix(abs, ".deb") {
		return "", fmt.Errorf("VALIDATION_FAILED: --artifact must be a .deb path")
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("VALIDATION_FAILED: staged artifact unreadable: %w", err)
	}
	release, err := policy.LockDir(svc.State.Root)
	if err != nil {
		return "", fmt.Errorf("update lock: %w", err)
	}
	defer release()
	j, err := openUpdateJournal(svc)
	if err != nil {
		return "", fmt.Errorf("install journal unavailable — refusing mutation: %w", err)
	}
	rep, err := replayJournal(svc)
	if err != nil {
		return "", err
	}
	if rep.Corrupt {
		return "", fmt.Errorf("JOURNAL_CORRUPT: install journal has torn records — run `ara update recover` after inspecting %s", updateJournalPath(svc))
	}
	if rep.Open != nil {
		return "", fmt.Errorf("INSTALL_INTERRUPTED: a previous install (artifact %s) never completed — run `ara update recover` first", rep.Open.Identity)
	}

	identity, err := fileSHA256(abs)
	if err != nil {
		return "", fmt.Errorf("artifact identity: %w", err)
	}
	component := componentOfArtifact(abs)

	updateDir := filepath.Join(svc.State.Root, "updates")
	// retain a LOCAL verified copy of the candidate BEFORE any mutation:
	// the ACTUAL dpkg install uses this copy (D01: immutable artifact for
	// the install), and the LKG promotion after a healthy gate copies it
	candCopy := filepath.Join(updateDir, "candidate.deb")
	if data, rerr := os.ReadFile(abs); rerr != nil {
		return "", rerr
	} else if werr := atomicWriteFile(candCopy, data, 0o600); werr != nil {
		return "", werr
	}
	copyIdentity, err := fileSHA256(candCopy)
	if err != nil || copyIdentity != identity {
		return "", fmt.Errorf("INTERNAL: candidate copy identity mismatch")
	}

	if err := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "install-start",
		Detail: abs, Identity: identity, OK: true, Outcome: "known-ok", Component: component, V: 1}); err != nil {
		return "", fmt.Errorf("journal write failed — refusing mutation: %w", err)
	}

	// install the VERIFIED LOCAL COPY (not the operator's temp file)
	out, derr := run("dpkg", "--install", candCopy)
	if derr != nil {
		// dpkg started and failed: the system MAY be partially changed —
		// the transaction stays OPEN until recovery (D01 #3). No LKG
		// promotion, no new install before recovery.
		if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: out, Identity: identity, OK: false, Outcome: "known-fail", Component: component, V: 1}); aerr != nil {
			return "", fmt.Errorf("journal write failed after dpkg failure: %w", aerr)
		}
		journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "install-fail",
			Detail: "dpkg failed after starting — partial effect possible, recovery required", Identity: identity, OK: false, Outcome: "known-fail", Effect: effectBool(true), Component: component, V: 1})
		return "", fmt.Errorf("INSTALL_FAILED: %s; run `ara update recover` before the next install", strings.TrimSpace(out))
	}
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "dpkg-install", Detail: out, Identity: identity, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed after dpkg — run `ara update recover`: %w", aerr)
	}

	// health gate for the NEW version (restart intents journaled inside)
	failed := restartARAServices(svc, j, run)
	if len(failed) == 0 {
		// COMMIT: only now the previous package is replaced (C01); the
		// commit is DURABLE — a journal write failure here is an error,
		// never success (D01 #2)
		if err := promoteLKG(svc, component, candCopy); err != nil {
			journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "commit", Detail: "LKG promotion failed: " + err.Error(), Identity: identity, OK: false, Outcome: "known-fail", Component: component, V: 1})
			return "", fmt.Errorf("COMMIT_FAILED: LKG promotion: %w", err)
		}
		if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "commit", Detail: "health ok; LKG promoted", Identity: identity, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
			return "", fmt.Errorf("COMMIT_FAILED: install succeeded but the durable commit could not be recorded — run `ara update recover`: %w", aerr)
		}
		return out, nil
	}
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "health", Detail: "units not active: " + strings.Join(failed, ","), Identity: identity, OK: false, Outcome: "known-fail", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed after health failure: %w", aerr)
	}

	// ROLLBACK: the retained LKG of THIS component (D01/E01); the legacy
	// shared slot is used only after PROVEN component compatibility
	prevPath, hasPrev := "", false
	for _, cand := range lkgCandidates(svc, component, run) {
		if _, serr := os.Stat(cand); serr != nil {
			continue
		}
		if !lkgCompatible(svc, run, cand, component) {
			continue // foreign bytes: never installed as another component
		}
		prevPath, hasPrev = cand, true
		break
	}
	if !hasPrev {
		journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "rollback", Detail: "no previous package retained (first install)", Identity: identity, OK: false, Outcome: "known-fail", Component: component, V: 1})
		return "", fmt.Errorf("HEALTH_FAILED: units %s (first install: no previous package to roll back to)", strings.Join(failed, ","))
	}
	prevIdentity, _ := fileSHA256(prevPath)
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "rollback", Detail: "restoring retained LKG " + prevIdentity, Identity: prevIdentity, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed before rollback: %w", aerr)
	}
	rbOut, rbErr := run("dpkg", "--install", prevPath)
	if rbErr != nil {
		journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "rollback", Detail: rbOut, Identity: prevIdentity, OK: false, Outcome: "known-fail", Component: component, V: 1})
		return "", fmt.Errorf("INSTALL_FAILED_AND_ROLLBACK_FAILED: %s", strings.TrimSpace(rbOut))
	}
	// C01/D01: the RESTORED version must actually work — its own restart
	// and health gate decide whether recovery succeeded.
	rbFailed := restartARAServices(svc, j, run)
	if len(rbFailed) > 0 {
		if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "rollback", Detail: "restored units unhealthy: " + strings.Join(rbFailed, ","), Identity: prevIdentity, OK: false, Outcome: "known-fail", Component: component, V: 1}); aerr != nil {
			return "", fmt.Errorf("journal write failed after failed rollback: %w", aerr)
		}
		return "", fmt.Errorf("ROLLBACK_INCOMPLETE: restored version unhealthy (units %s)", strings.Join(rbFailed, ","))
	}
	// the verified rollback CLOSES the transaction (D01 #4): a following
	// healthy install is admitted
	if aerr := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "rollback-done", Detail: "restored version healthy", Identity: prevIdentity, OK: true, Outcome: "known-ok", Component: component, V: 1}); aerr != nil {
		return "", fmt.Errorf("journal write failed after verified rollback — run `ara update recover`: %w", aerr)
	}
	return "", fmt.Errorf("INSTALL_FAILED_ROLLED_BACK: units %s; verified restored version %s", strings.Join(failed, ","), shortSHA(prevIdentity))
}

// promoteLKG atomically promotes the verified candidate copy to the
// component's LKG slot (errors are never ignored — D01).
func promoteLKG(svc *service.Service, component, candCopy string) error {
	data, err := os.ReadFile(candCopy)
	if err != nil {
		return err
	}
	return atomicWriteFile(lkgPath(svc, component), data, 0o600)
}

// effectBool returns a pointer for the typed Effect field.
func effectBool(v bool) *bool { return &v }

// installResultOK reports whether the open transaction has a SUCCESSFUL
// dpkg-install result recorded (I01): a failed/unknown attempt does not
// prove the candidate was installed and must be retried.
func installResultOK(rep *journalReplay) bool {
	return rep.InstallSucceeded && rep.Phase == "install"
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// atomicWriteFile: temp file in the same dir + fsync file + fsync dir +
// rename + fsync dir (C02/D01 durability for LKG and candidate copies).
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".upd-*")
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
	if err := os.Chmod(tmp, mode); err != nil {
		return err
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

// restartARAServices restarts the installed ARA units that exist and
// returns the names whose health gate (`systemctl is-active`) failed.
// Each restart carries its own durable intent + outcome (D01).
func restartARAServices(svc *service.Service, j *txlog.Log, run updateRunner) []string {
	var failed []string
	for _, unit := range []string{"ara-agent", "ara-edge", "ara-control"} {
		if _, err := run("systemctl", "list-unit-files", unit+".service"); err != nil {
			continue // not installed on this machine
		}
		if j != nil {
			if err := journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "restart", Detail: "intent " + unit, OK: true, Outcome: "known-ok"}); err != nil {
				failed = append(failed, unit)
				continue
			}
		}
		if _, err := run("systemctl", "restart", unit+".service"); err != nil {
			if j != nil {
				journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "restart", Detail: unit + " failed", OK: false, Outcome: "known-fail"})
			}
			failed = append(failed, unit)
			continue
		}
		deadline := time.Now().Add(10 * time.Second)
		active := false
		for time.Now().Before(deadline) {
			out, err := run("systemctl", "is-active", unit+".service")
			if err == nil && strings.TrimSpace(out) == "active" {
				active = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if j != nil {
			outcome := "known-ok"
			if !active {
				outcome = "known-fail"
			}
			journalAppend(j, updateJournalEntry{At: time.Now().UTC(), Step: "restart", Detail: unit, OK: active, Outcome: outcome})
		}
		if !active {
			failed = append(failed, unit)
		}
	}
	return failed
}
