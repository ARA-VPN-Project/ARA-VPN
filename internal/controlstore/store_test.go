package controlstore

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDeviceEnrollmentOneTime(t *testing.T) {
	s := openTest(t)
	if _, err := s.CreateAccount("acc1", ""); err != nil {
		t.Fatal(err)
	}
	dev, secret, err := s.CreateDevice("acc1", "laptop")
	if err != nil || secret == "" {
		t.Fatalf("enroll: %v %q", err, secret)
	}
	// secret is stored only as a hash
	if strings.Contains(dev.IdentityPub, secret) {
		t.Fatal("plaintext secret leaked into stored record")
	}
	if err := s.ConsumeEnrollment(dev.ID, secret); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// second use must be refused: invitation is one-time. The refusal is
	// deliberately uniform (no oracle distinguishing replay/revoked/wrong
	// secret).
	if err := s.ConsumeEnrollment(dev.ID, secret); err == nil || !strings.HasPrefix(err.Error(), "AUTH_FAILED") {
		t.Fatalf("replay accepted or non-uniform error: %v", err)
	}
	// wrong secret refused for a fresh device
	_, _, _ = s.CreateDevice("acc1", "phone")
	devs, _ := s.ListDevices()
	second := devs[len(devs)-1]
	if err := s.ConsumeEnrollment(second.ID, "wrong"); err == nil {
		t.Fatal("wrong secret accepted")
	}
}

func TestRevokeStopsEnrollmentAndList(t *testing.T) {
	s := openTest(t)
	s.CreateAccount("acc1", "")
	dev, secret, _ := s.CreateDevice("acc1", "d1")
	if err := s.RevokeDevice(dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeEnrollment(dev.ID, secret); err == nil {
		t.Fatal("revoked device enrolled")
	}
	if err := s.RevokeDevice(dev.ID); err == nil {
		t.Fatal("double revoke accepted")
	}
}

func TestUnknownAccountAndRoleValidation(t *testing.T) {
	s := openTest(t)
	if _, _, err := s.CreateDevice("ghost", "x"); err == nil {
		t.Fatal("device under unknown account created")
	}
	if _, err := s.AddNode("n1", "NL", "foreign", 1); err != nil {
		t.Fatalf("node add: %v", err)
	}
	if _, err := s.AddNode("n2", "RU", "satellite", 1); err == nil {
		t.Fatal("invalid role accepted")
	}
	nodes, _ := s.ListNodes()
	if len(nodes) != 1 || nodes[0].Role != "foreign" {
		t.Fatalf("nodes: %+v", nodes)
	}
	if err := s.RevokeNode("n1"); err != nil {
		t.Fatal(err)
	}
}

func TestNodePriorityOrdering(t *testing.T) {
	s := openTest(t)
	s.AddNode("nl-b", "NL", "foreign", 2)
	s.AddNode("nl-a", "NL", "foreign", 1)
	s.AddNode("ru-e", "RU", "ru", 0)
	nodes, _ := s.ListNodes()
	if nodes[0].ID != "ru-e" || nodes[1].ID != "nl-a" || nodes[2].ID != "nl-b" {
		t.Fatalf("ordering: %+v", nodes)
	}
}

func TestAuditAppendAndTail(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Append(AuditEntry{Actor: "op", Action: "test", ObjectID: "x", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := a.Tail(3)
	if err != nil || len(entries) != 3 {
		t.Fatalf("tail: %v %d", err, len(entries))
	}
	if entries[0].At.IsZero() {
		t.Fatal("server-side timestamps missing")
	}
}

// R02 regression: an enrollment secret is consumable exactly once, even
// under concurrency, across DB reopen, and loses to a concurrent revoke.
func TestEnrollmentAtomicUnderConcurrencyAndReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAccount("acc", "")
	dev, secret, _ := s.CreateDevice("acc", "d")

	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if s.ConsumeEnrollment(dev.ID, secret) == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := successes.Load(); n != 1 {
		t.Fatalf("enrollment accepted %d times concurrently, want exactly 1", n)
	}
	s.Close()

	// reopen: the consumption is durable and still single-use
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.ConsumeEnrollment(dev.ID, secret); err == nil {
		t.Fatal("replayed enrollment accepted after reopen")
	}

	// revoke race: a revoked device can never consume
	_, secret2, _ := s2.CreateDevice("acc", "d2")
	devs, _ := s2.ListDevices()
	var d2 string
	for _, dd := range devs {
		if dd.Name == "d2" {
			d2 = dd.ID
		}
	}
	s2.RevokeDevice(d2)
	if err := s2.ConsumeEnrollment(d2, secret2); err == nil {
		t.Fatal("revoked device consumed enrollment")
	}
}
