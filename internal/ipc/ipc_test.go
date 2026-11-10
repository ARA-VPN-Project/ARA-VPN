package ipc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func osStat(p string) (os.FileInfo, error) { return os.Stat(p) }
func osIsNotExist(err error) bool          { return err != nil && os.IsNotExist(err) }

func TestRoundTripAndUnknownMethod(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	methods := map[string]Handler{
		"echo": func(ctx context.Context, params json.RawMessage) (any, *IpcError) {
			var p map[string]any
			json.Unmarshal(params, &p)
			return p, nil
		},
		"fail": func(ctx context.Context, params json.RawMessage) (any, *IpcError) {
			return nil, &IpcError{Code: "CONFLICT", Message: "nope"}
		},
	}
	srv, err := NewServer(sock, methods)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serr := make(chan error, 1)
	go func() { serr <- srv.Serve(ctx) }()

	// wait for socket to appear
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := Dial(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never became dialable")
		}
		time.Sleep(10 * time.Millisecond)
	}

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	res, ierr, err := c.Call("echo", map[string]any{"x": 1})
	if err != nil || ierr != nil {
		t.Fatalf("echo: %v %v", err, ierr)
	}
	var out map[string]any
	json.Unmarshal(res, &out)
	if out["x"] != float64(1) {
		t.Fatalf("echo result: %v", out)
	}

	_, ierr, err = c.Call("fail", nil)
	if err != nil || ierr == nil || ierr.Code != "CONFLICT" {
		t.Fatalf("fail: %v %v", err, ierr)
	}

	_, ierr, _ = c.Call("nope", nil)
	if ierr == nil || ierr.Code != "UNSUPPORTED_CAPABILITY" {
		t.Fatalf("unknown method: %v", ierr)
	}

	cancel()
	select {
	case err := <-serr:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not stop")
	}
	if _, err := osStat(sock); !osIsNotExist(err) {
		t.Fatalf("socket file not removed on close: %v", err)
	}
}

func TestSocketFilePermissions(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	srv, err := NewServer(sock, map[string]Handler{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	info, err := osStat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600", perm)
	}
}
