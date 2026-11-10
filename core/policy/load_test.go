package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// ParseState is the shared reader for committed policy state: the store
// envelope and the legacy bare document must parse identically everywhere
// (edge data path included), and garbage must be an error, never a
// permissive fallback.
func TestParseStateAcceptsEnvelopeAndBare(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.Rules = []Rule{{ID: "r1", Enabled: true, DomainExact: []string{"blocked.example"}, Action: ActionBlock}}
	if _, err := s.ValidateAndApplyIdentity(p, 0, "plan-1", "key-1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "policy.current.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, id, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "r1" {
		t.Fatalf("envelope policy misread: %+v", got)
	}
	if id == nil || id.PlanID != "plan-1" {
		t.Fatalf("envelope identity lost: %+v", id)
	}

	bare := []byte(`{"schema_version":1,"revision":3,"allow_ru_fallback":true,"rules":[]}`)
	got2, id2, err := ParseState(bare)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Revision != 3 || id2 != nil {
		t.Fatalf("bare policy misread: %+v id=%+v", got2, id2)
	}

	if _, _, err := ParseState([]byte("{broken")); err == nil {
		t.Fatal("invalid document accepted")
	}
}
