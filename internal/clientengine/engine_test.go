package clientengine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// stubEngine is a benign long-running process standing in for the pinned
// engine in unit tests (no TUN, no network).
func stubEngine(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "stub-engine.sh")
	script := "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 0.2; done\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeProfile(t *testing.T, root, name string, enginePath string, waitMode string) {
	t.Helper()
	d := filepath.Join(root, "profiles")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := Profile{
		EnginePath: enginePath, ServerAddr: "10.60.0.1:443", ServerName: "edge.ara.lab",
		CAPath: "/tmp/ara-ca.crt", UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		TUNName: "ara-tun", TUNAddr4: "10.99.0.1/30", MTU: 1400, WaitMode: waitMode,
	}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(d, name+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEngineStartStopStatusLifecycle(t *testing.T) {
	root := t.TempDir()
	stub := stubEngine(t)
	writeProfile(t, root, "default", stub, "none")
	e := New(root)

	if _, err := e.Status(); err != nil || err == ErrNotConnected {
		t.Fatalf("status before connect: err=%v (want nil, not connected)", err)
	}
	if _, err := e.Stop(); err != ErrNotConnected {
		t.Fatalf("stop without connect must be ErrNotConnected, got %v", err)
	}
	v, err := e.Start("default")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !v.Running || v.PID == 0 || v.ProfileName != "default" {
		t.Fatalf("start view: %+v", v)
	}
	st, err := e.Status()
	if err != nil || !st.Running || st.PID != v.PID {
		t.Fatalf("status while running: %+v err=%v", st, err)
	}
	// generated config and session files are private
	for _, f := range []string{filepath.Join(root, "engine", "client.json"), filepath.Join(root, "engine", "session.json")} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("missing %s", f)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s perms %v", f, fi.Mode().Perm())
		}
	}
	v, err = e.Stop()
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if st, _ := e.Status(); st.Running {
		t.Fatalf("status after stop must show not running: %+v", st)
	}
	// the process really is gone: the killed child is a zombie until
	// reaped by its parent (this test process), so reap it first
	deadline := time.Now().Add(2 * time.Second)
	for {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(v.PID, &ws, syscall.WNOHANG, nil)
		if err == syscall.ECHILD || (err == nil && wpid == v.PID) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine process survived Stop (never reaped)")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEngineAlreadyConnectedConflict(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "default", stubEngine(t), "none")
	e := New(root)
	if _, err := e.Start("default"); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if _, err := e.Start("default"); !errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("second start must be ErrAlreadyConnected, got %v", err)
	}
}

func TestEngineStaleSessionCleanedOnStart(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "default", stubEngine(t), "none")
	e := New(root)
	// forge a session whose PID is dead: stale, must be cleaned by Start
	if err := os.MkdirAll(filepath.Join(root, "engine"), 0o700); err != nil {
		t.Fatal(err)
	}
	dead := session{PID: 999999, StartTime: 1, ProfileName: "default", StartedAt: time.Now()}
	b, _ := json.Marshal(dead)
	if err := os.WriteFile(filepath.Join(root, "engine", "session.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := e.Start("default")
	if err != nil {
		t.Fatalf("start over stale session: %v", err)
	}
	defer e.Stop()
	if !v.Running {
		t.Fatalf("start over stale: %+v", v)
	}
}

func TestEngineStopNeverTouchesForeignPID(t *testing.T) {
	root := t.TempDir()
	e := New(root)
	if err := os.MkdirAll(filepath.Join(root, "engine"), 0o700); err != nil {
		t.Fatal(err)
	}
	// record the CURRENT test process as the session owner; Stop must
	// refuse to signal it (start-time mismatch check only strengthens
	// this: same PID, wrong recorded start time is not ours)
	s := session{PID: os.Getpid(), StartTime: 424242, ProfileName: "x", StartedAt: time.Now()}
	b, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(root, "engine", "session.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := e.Stop()
	if err != nil {
		t.Fatalf("stop with stale foreign session: %v", err)
	}
	if !v.StaleCleaned {
		t.Fatalf("foreign PID must be reported stale-cleaned: %+v", v)
	}
	// the test process is obviously still alive
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatal("self must be alive")
	}
	if _, err := os.Stat(filepath.Join(root, "engine", "session.json")); !os.IsNotExist(err) {
		t.Fatal("stale session not removed")
	}
}

func TestEngineProfileValidation(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, "broken", "/nonexistent", "none")
	e := New(root)
	if _, err := e.Start("broken"); err == nil {
		t.Fatal("missing engine binary must fail")
	}
	// bad profile name is refused before any file access
	if _, err := e.Start("../escape"); err == nil {
		t.Fatal("path traversal profile name accepted")
	}
	if _, err := e.Start(""); err == nil {
		t.Fatal("empty profile name accepted")
	}
}
