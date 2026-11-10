package fedauth

import (
	"strings"
	"testing"
	"time"
)

func TestIdentityRoundtripAndSignVerify(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir, "ru-1")
	if err != nil || a.PanelID != "ru-1" {
		t.Fatalf("create: %v", err)
	}
	// reload returns the same identity
	b, err := LoadOrCreate(dir, "")
	if err != nil || b.PrivHex != a.PrivHex || b.PanelID != "ru-1" {
		t.Fatalf("reload: %v %+v", err, b)
	}
	if len(a.Public()) == 0 || len(a.PublicHex()) != 64 {
		t.Fatalf("public key: %q", a.PublicHex())
	}
	body := []byte(`{"k":"v"}`)
	ts := time.Now().Unix()
	sig := a.Sign("POST", "/api/fed/v1/x", ts, "n-1", body)
	if err := Verify(a.PublicHex(), "POST", "/api/fed/v1/x", ts, "n-1", sig, body, time.Now()); err != nil {
		t.Fatalf("verify own signature: %v", err)
	}
	// tampered body refused
	if err := Verify(a.PublicHex(), "POST", "/api/fed/v1/x", ts, "n-1", sig, []byte(`{"k":"w"}`), time.Now()); err == nil {
		t.Fatal("tampered body accepted")
	}
	// stale timestamp refused (replay window)
	if err := Verify(a.PublicHex(), "POST", "/api/fed/v1/x", ts-Skew.Milliseconds()/1000-3600, "n-1", sig, body, time.Now()); err == nil {
		t.Fatal("stale timestamp accepted")
	}
	// empty nonce refused
	if err := Verify(a.PublicHex(), "POST", "/api/fed/v1/x", ts, "", sig, body, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "nonce") {
		t.Fatalf("empty nonce must be refused: %v", err)
	}
}
