package main

// B42: the update apply workflow is REAL (dpkg → restart → health →
// rollback) and verified with injected runners — no root, no system
// changes: the fake dpkg/systemctl record invocations and simulate a bad
// health for the rollback path.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aravpn/internal/service"
)

var errFakeFail = errors.New("fake failure")

func updTestService(t *testing.T) *service.Service {
	t.Helper()
	svc, err := service.New(service.StateDir{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestUpdateApplyWorkflowInstallsRestartsAndJournals(t *testing.T) {
	svc := updTestService(t)
	staged := filepath.Join(t.TempDir(), "ara-client_2.deb")
	os.WriteFile(staged, []byte("deb-payload-2"), 0o600)
	var calls []string
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "dpkg":
			return "setup", nil
		case name == "systemctl" && args[0] == "list-unit-files":
			if args[1] == "ara-edge.service" {
				return "", errFakeFail // not installed on this machine
			}
			return "1 unit files listed.", nil
		case name == "systemctl" && args[0] == "restart":
			return "", nil
		case name == "systemctl" && args[0] == "is-active":
			return "active", nil
		}
		return "", nil
	}
	out, err := updateApplyWorkflow(svc, staged, run)
	if err != nil {
		t.Fatalf("apply workflow: %v", err)
	}
	if !strings.Contains(out, "setup") {
		t.Fatalf("dpkg output not surfaced: %q", out)
	}
	// D01: the ACTUAL install uses the verified candidate COPY inside the
	// state dir, never the operator's temp path
	candCopy := filepath.Join(svc.State.Root, "updates", "candidate.deb")
	if !strings.Contains(strings.Join(calls, "; "), "dpkg --install "+candCopy) {
		t.Fatalf("dpkg install not invoked with the verified copy: %v", calls)
	}
	for _, c := range calls {
		if strings.Contains(c, "dpkg --install "+staged) {
			t.Fatalf("operator temp path was installed directly: %v", calls)
		}
	}
	if !strings.Contains(strings.Join(calls, "; "), "systemctl restart ara-agent.service") {
		t.Fatalf("ara-agent not restarted: %v", calls)
	}
	if strings.Contains(strings.Join(calls, "; "), "ara-edge.service") &&
		strings.Contains(strings.Join(calls, "; "), "restart ara-edge") {
		t.Fatal("not-installed unit must be skipped")
	}
	// the installed package is retained as the next rollback target
	if _, err := os.Stat(filepath.Join(svc.State.Root, "updates", "previous.deb")); err != nil {
		t.Fatal("rollback target not retained")
	}
	// the journal records the whole chain (C02: durable intent → outcome;
	// successful health ends in a commit that promotes the LKG)
	j, _ := os.ReadFile(updateJournalPath(svc))
	for _, step := range []string{"install-start", "dpkg-install", "commit"} {
		if !strings.Contains(string(j), `"`+step+`"`) {
			t.Fatalf("journal missing step %s: %s", step, j)
		}
	}
}

func TestUpdateApplyWorkflowRollsBackOnBadHealth(t *testing.T) {
	svc := updTestService(t)
	prev := filepath.Join(svc.State.Root, "updates", "previous.deb")
	os.MkdirAll(filepath.Dir(prev), 0o700)
	os.WriteFile(prev, []byte("deb-payload-1"), 0o600)
	staged := filepath.Join(t.TempDir(), "ara-client_2.deb")
	os.WriteFile(staged, []byte("deb-payload-2"), 0o600)
	var calls []string
	lastInstall := ""
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "dpkg":
			lastInstall = args[1]
			return "", nil
		case name == "systemctl" && args[0] == "list-unit-files":
			return "1 unit files listed.", nil
		case name == "systemctl" && args[0] == "restart":
			return "", nil
		case name == "systemctl" && args[0] == "is-active":
			// the NEW version comes up unhealthy; the RESTORED (rollback)
			// version is healthy again — C01/D01: recovery is verified on
			// wire. The actual install uses the verified candidate COPY.
			if lastInstall != prev {
				return "failed", errFakeFail
			}
			return "active", nil
		}
		return "", nil
	}
	_, err := updateApplyWorkflow(svc, staged, run)
	if err == nil || !strings.Contains(err.Error(), "INSTALL_FAILED_ROLLED_BACK") {
		t.Fatalf("expected typed rolled-back failure with verified restore, got %v", err)
	}
	if !strings.Contains(strings.Join(calls, "; "), "dpkg --install "+prev) {
		t.Fatalf("rollback package not installed: %v", calls)
	}
	// the new artifact bytes were NOT promoted over the retained LKG
	got, _ := os.ReadFile(prev)
	if string(got) != "deb-payload-1" {
		t.Fatalf("LKG replaced before health commit: %q", got)
	}
}

func TestUpdateApplyFirstInstallNoRollbackTarget(t *testing.T) {
	svc := updTestService(t)
	staged := filepath.Join(t.TempDir(), "ara-client_1.deb")
	os.WriteFile(staged, []byte("deb-payload-1"), 0o600)
	run := func(name string, args ...string) (string, error) {
		switch {
		case name == "dpkg":
			return "", nil
		case name == "systemctl" && args[0] == "list-unit-files":
			return "1 unit files listed.", nil
		case name == "systemctl" && args[0] == "restart":
			return "", nil
		case name == "systemctl" && args[0] == "is-active":
			return "failed", errFakeFail // broken first version
		}
		return "", nil
	}
	_, err := updateApplyWorkflow(svc, staged, run)
	if err == nil || !strings.Contains(err.Error(), "no previous package") {
		t.Fatalf("first-install health failure must report missing rollback target: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(svc.State.Root, "updates", "previous.deb")); statErr == nil {
		t.Fatal("broken first install must not be promoted to LKG")
	}
}

func TestUpdateApplyInterruptedInstallRequiresRecover(t *testing.T) {
	svc := updTestService(t)
	staged := filepath.Join(t.TempDir(), "ara-client_2.deb")
	os.WriteFile(staged, []byte("deb-payload-2"), 0o600)
	// simulate a crash mid-install: an install-start with no terminal entry
	os.MkdirAll(filepath.Join(svc.State.Root, "updates"), 0o700)
	jstart := `{"at":"2026-11-02T00:00:00Z","step":"install-start","ok":true,"outcome":"known-ok"}`
	os.WriteFile(updateJournalPath(svc), []byte(jstart+"\n"), 0o600)
	_, err := updateApplyWorkflow(svc, staged, func(name string, args ...string) (string, error) { return "", nil })
	if err == nil || !strings.Contains(err.Error(), "INSTALL_INTERRUPTED") {
		t.Fatalf("unfinished install must block a new mutation: %v", err)
	}
	// recovery completes the interrupted install
	run := func(name string, args ...string) (string, error) {
		switch {
		case name == "dpkg":
			return "", nil
		case name == "systemctl":
			if args[0] == "is-active" {
				return "active", nil
			}
			return "", nil
		}
		return "", nil
	}
	if _, err := updateRecoverWorkflow(svc, run); err != nil {
		t.Fatalf("recover: %v", err)
	}
	// after recovery a new apply is possible again
	run2 := func(name string, args ...string) (string, error) { return run(name, args...) }
	if _, err := updateApplyWorkflow(svc, staged, run2); err != nil {
		t.Fatalf("apply after recover: %v", err)
	}
}

func TestUpdateApplyWorkflowRefusesNonRootWithoutRunner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	svc := updTestService(t)
	staged := filepath.Join(t.TempDir(), "ara-client_2.deb")
	os.WriteFile(staged, []byte("x"), 0o600)
	_, err := updateApplyWorkflow(svc, staged, nil)
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("non-root must be refused with the exact command: %v", err)
	}
}
