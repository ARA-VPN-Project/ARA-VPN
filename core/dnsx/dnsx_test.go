package dnsx

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestCacheKeySeparatesRevisionGenerationExit(t *testing.T) {
	base := CacheKey{CanonicalDomain: "example.test", QType: QTypeA, PolicyRevision: 1, Generation: 1, ExitID: "nl-a", DeviceID: "dev1"}

	rev := base
	rev.PolicyRevision = 2
	if rev.String() == base.String() {
		t.Fatal("cache shared across policy revisions")
	}
	gen := base
	gen.Generation = 2
	if gen.String() == base.String() {
		t.Fatal("cache shared across route generations")
	}
	ext := base
	ext.ExitID = "ru-e"
	if ext.String() == base.String() {
		t.Fatal("cache shared across exits")
	}
	dev := base
	dev.DeviceID = "dev2"
	if dev.String() == base.String() {
		t.Fatal("cache shared across devices")
	}
	q := base
	q.QType = QTypeAAAA
	if q.String() == base.String() {
		t.Fatal("A and AAAA share a cache entry")
	}
}

func TestScopeForMatchesRoutingConvention(t *testing.T) {
	k, err := ScopeFor("exit:nl-a", "media.example", QTypeA, 4, 9, "dev1")
	if err != nil || k.ExitID != "nl-a" {
		t.Fatalf("foreign scope: %+v err=%v", k, err)
	}
	k, err = ScopeFor("ru:ru-e", "example.test", QTypeAAAA, 4, 10, "dev1")
	if err != nil || k.ExitID != "ru-e" {
		t.Fatalf("ru scope: %+v err=%v", k, err)
	}
	if _, err := ScopeFor("none", "x", QTypeA, 1, 1, "d"); err == nil {
		t.Fatal("blocked scope produced a cache key; blocked flows must not resolve")
	}
	if _, err := ScopeFor("bogus:x", "x", QTypeA, 1, 1, "d"); err == nil {
		t.Fatal("unknown scope kind accepted")
	}
}

func TestFakeIPPoolAllocateLookupTTL(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pool, err := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/15"), 4, 30*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	a1, err := pool.Allocate("media.example", "dev1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.base.Contains(a1) {
		t.Fatalf("allocated outside pool: %v", a1)
	}
	// same domain+device reuses the address
	a2, _ := pool.Allocate("media.example", "dev1", 2)
	if a1 != a2 {
		t.Fatalf("reuse changed address: %v vs %v", a1, a2)
	}
	domain, gen, ok := pool.Lookup(a1)
	if !ok || domain != "media.example" || gen != 2 {
		t.Fatalf("lookup: %q %d %v", domain, gen, ok)
	}
	// different device gets a different mapping
	a3, _ := pool.Allocate("media.example", "dev2", 1)
	if a3 == a1 {
		t.Fatal("two devices shared one fake IP")
	}
	// TTL expiry releases the entry
	now = now.Add(31 * time.Second)
	if _, _, ok := pool.Lookup(a1); ok {
		t.Fatal("expired mapping served")
	}
	a4, err := pool.Allocate("other.example", "dev1", 1)
	if err != nil {
		t.Fatalf("allocate after expiry: %v", err)
	}
	_ = a4
}

func TestFakeIPPoolBoundedNoWraparound(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pool, err := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/24"), 3, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	seen := map[netip.Addr]string{}
	var firstAddr netip.Addr
	for i := 0; i < 3; i++ {
		d := string(rune('a'+i)) + ".example"
		a, err := pool.Allocate(d, "dev1", 1)
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		seen[a] = d
		if d == "a.example" {
			firstAddr = a
		}
	}
	// pool full with LIVE bindings: a 4th distinct domain must be refused
	// with the typed error, never rebind a live address (review R05)
	if _, err := pool.Allocate("d.example", "dev1", 1); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("expected ErrPoolExhausted, got %v", err)
	}
	// every existing binding still resolves to its own domain
	for addr, d := range seen {
		got, _, ok := pool.Lookup(addr)
		if !ok || got != d {
			t.Fatalf("live binding changed: %s -> %q (want %q)", addr, got, d)
		}
	}
	// after the TTL elapses the slots are reclaimable
	now = now.Add(2 * time.Minute)
	a4, err := pool.Allocate("d.example", "dev1", 1)
	if err != nil {
		t.Fatalf("allocate after expiry: %v", err)
	}
	if _, bound := seen[a4]; !bound {
		t.Fatalf("reclaimed address %v is not from the pool range", a4)
	}
	// the LIVE binding of the reclaimed slot must resolve to its new
	// domain; which free slot the pool hands out is legitimate reuse, so
	// firstAddr may now belong to d.example — only identity of live
	// bindings and non-resolution of still-expired slots are asserted
	if dom, _, ok := pool.Lookup(a4); !ok || dom != "d.example" {
		t.Fatalf("reclaimed binding wrong: %q ok=%v", dom, ok)
	}
	if firstAddr != a4 {
		if _, _, ok := pool.Lookup(firstAddr); ok {
			t.Fatal("expired mapping still resolves after reclaim")
		}
	}
}

func TestFakeIPPoolReleaseForDevice(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pool, _ := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/15"), 16, time.Hour, func() time.Time { return now })
	a1, _ := pool.Allocate("x.example", "dev1", 1)
	a2, _ := pool.Allocate("y.example", "dev2", 1)
	pool.ReleaseForDevice("dev1")
	if _, _, ok := pool.Lookup(a1); ok {
		t.Fatal("released device mapping still resolves")
	}
	if _, _, ok := pool.Lookup(a2); !ok {
		t.Fatal("other device mapping was released")
	}
}

func TestFakeIPPrefixFirstAddressNotUsed(t *testing.T) {
	now := time.Unix(1700000000, 0)
	pool, _ := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/24"), 8, time.Hour, func() time.Time { return now })
	a, err := pool.Allocate("first.example", "dev1", 1)
	if err != nil {
		t.Fatal(err)
	}
	// offset starts at 1: base network address itself is never allocated
	if a == netip.MustParseAddr("198.18.0.0") {
		t.Fatalf("network address allocated: %v", a)
	}
}

// S08 regressions: constructor refuses impossible configurations and
// every allocation provably stays inside the configured prefix.
func TestFakeIPPoolCapacityEnforced(t *testing.T) {
	// /30 has 4 addresses, 2 usable: size 5 must be refused by the
	// constructor, never produce out-of-range addresses
	if _, err := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/30"), 5, time.Hour, nil); err == nil {
		t.Fatal("/30 with size 5 accepted")
	}
	// exactly at capacity works and stays in range
	pool, err := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/30"), 2, time.Hour, nil)
	if err != nil {
		t.Fatalf("/30 with size 2 refused: %v", err)
	}
	base := netip.MustParsePrefix("198.18.0.0/30")
	for i := 0; i < 2; i++ {
		a, err := pool.Allocate(string(rune('a'+i))+".example", "d", 1)
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if !base.Contains(a) {
			t.Fatalf("allocation outside configured prefix: %s", a)
		}
		if a == netip.MustParseAddr("198.18.0.0") || a == netip.MustParseAddr("198.18.0.3") {
			t.Fatalf("network/broadcast address allocated: %s", a)
		}
	}
	// a third domain is refused with the typed error, never out-of-range
	if _, err := pool.Allocate("c.example", "d", 1); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("expected ErrPoolExhausted, got %v", err)
	}
	// absurd sizes are refused at construction (resource ceiling)
	if _, err := NewFakeIPPool(netip.MustParsePrefix("198.18.0.0/15"), 1<<25, time.Hour, nil); err == nil {
		t.Fatal("oversized pool accepted")
	}
}
