// Package dnsx implements DNS-as-part-of-route semantics
// (docs/ROUTING_DNS.md): cache keys scoped by policy revision, route
// generation and exit, and the bounded fake-IP association model that gives
// a flow trustworthy domain provenance.
package dnsx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// QType is the DNS question type relevant for cache separation.
type QType string

const (
	QTypeA    QType = "A"
	QTypeAAAA QType = "AAAA"
)

// CacheKey identifies one DNS cache entry. Cache is never shared across
// policy revisions, route generations or exits: a RU answer must never be
// reusable as a foreign answer and vice versa (docs/ROUTING_DNS.md).
type CacheKey struct {
	CanonicalDomain string
	QType           QType
	PolicyRevision  int64
	Generation      uint64
	ExitID          string
	DeviceID        string // device scoping where the mapping is per-device
}

// String renders the canonical cache key. Separator ':' cannot occur in
// any component (domains are IDNA ASCII; ids are hex/prefix-safe).
func (k CacheKey) String() string {
	return strings.Join([]string{
		k.CanonicalDomain, string(k.QType),
		fmt.Sprint(k.PolicyRevision), fmt.Sprint(k.Generation),
		k.ExitID, k.DeviceID,
	}, ":")
}

// ScopeFor returns the resolver scope binding for an exit decision:
// "ru:<exit>" for RU egress, "exit:<id>" for a foreign exit, "none" when
// blocked. It must match routing.Decision.DNSScope exactly.
func ScopeFor(dnsScope string, domain string, qtype QType, revision int64, generation uint64, device string) (CacheKey, error) {
	parts := strings.SplitN(dnsScope, ":", 2)
	if len(parts) != 2 {
		return CacheKey{}, fmt.Errorf("unknown dns scope %q", dnsScope)
	}
	var exitID string
	switch parts[0] {
	case "ru", "exit":
		exitID = parts[1]
	default:
		return CacheKey{}, fmt.Errorf("unknown dns scope kind %q", parts[0])
	}
	return CacheKey{
		CanonicalDomain: domain,
		QType:           qtype,
		PolicyRevision:  revision,
		Generation:      generation,
		ExitID:          exitID,
		DeviceID:        device,
	}, nil
}

// fakeEntry is one live fake-IP mapping.
type fakeEntry struct {
	domain     string
	deviceID   string
	generation uint64
	expires    time.Time
}

// ErrPoolExhausted is returned when every address of the pool is bound to
// a live (unexpired) mapping. The pool deliberately refuses instead of
// evicting: re-binding an unexpired address to another domain would make
// already-served DNS answers resolve flows to the wrong policy decision
// (review R05).
var ErrPoolExhausted = errors.New("fake-ip pool exhausted with live bindings")

// FakeIPPool allocates per-device unique fake IPs for domains, bounded by
// pool size and TTL. The pool base is a configuration decision; conflict
// detection against local networks is the preflight's job — the pool only
// guarantees internal uniqueness and bounded lifetime
// (docs/ROUTING_DNS.md).
type FakeIPPool struct {
	mu       sync.Mutex
	base     netip.Prefix
	ttl      time.Duration
	byAddr   map[netip.Addr]*fakeEntry
	byDomain map[string]netip.Addr // device-scoped domain → current addr
	free     []uint32              // offsets 1..size not currently bound
	size     uint32
	now      func() time.Time
}

// maxPoolSize is the resource ceiling on a single pool: fake-IP pools are
// per-device working sets, not address registries; a larger demand is a
// configuration error, not something to silently allocate.
const maxPoolSize = 1 << 20

// usableCapacity returns how many addresses of base the pool may hand
// out: the all-zero host address (network address) is never allocated,
// and IPv4 keeps the broadcast address reserved as well (review S08).
func usableCapacity(base netip.Prefix) (uint64, error) {
	if !base.IsValid() {
		return 0, fmt.Errorf("invalid prefix %v", base)
	}
	hostBits := base.Addr().BitLen() - base.Bits()
	if hostBits >= 32 {
		return 0, fmt.Errorf("prefix %v: host part does not fit 32-bit offsets", base)
	}
	total := uint64(1) << uint(hostBits)
	if base.Addr().Is4() || base.Addr().Is4In6() {
		if total < 2 {
			return 0, fmt.Errorf("prefix %v: smaller than a /31; no allocatable addresses", base)
		}
		return total - 2, nil // network + broadcast reserved
	}
	return total - 1, nil // v6: only the network address is reserved
}

// NewFakeIPPool builds a pool of size addresses from base. The prefix is
// normalized to its masked form and size is validated against the real
// usable capacity BEFORE anything is allocated — a misconfiguration is
// refused by the constructor, never turned into out-of-range addresses
// (review S08: /30 with size=5 used to hand out 198.18.0.5).
func NewFakeIPPool(base netip.Prefix, size uint32, ttl time.Duration, now func() time.Time) (*FakeIPPool, error) {
	if !base.IsValid() {
		return nil, fmt.Errorf("invalid fake-ip base prefix %v", base)
	}
	base = base.Masked()
	capacity, err := usableCapacity(base)
	if err != nil {
		return nil, fmt.Errorf("fake-ip pool %v: %w", base, err)
	}
	if size == 0 {
		return nil, fmt.Errorf("fake-ip pool %v: size must be >= 1", base)
	}
	if uint64(size) > capacity {
		return nil, fmt.Errorf("fake-ip pool %v: size %d exceeds usable capacity %d", base, size, capacity)
	}
	if size > maxPoolSize {
		return nil, fmt.Errorf("fake-ip pool %v: size %d exceeds the resource limit %d", base, size, maxPoolSize)
	}
	if now == nil {
		now = time.Now
	}
	free := make([]uint32, 0, size)
	// offsets 1..size within the usable range: the prefix's first address
	// (all-zero host bits) is never allocated, and for IPv4 the last
	// address (broadcast) is excluded by the capacity check.
	for off := uint32(1); off <= size; off++ {
		free = append(free, off)
	}
	return &FakeIPPool{
		base:     base,
		ttl:      ttl,
		byAddr:   make(map[netip.Addr]*fakeEntry, size),
		byDomain: map[string]netip.Addr{},
		free:     free,
		size:     size,
		now:      now,
	}, nil
}

func (p *FakeIPPool) key(domain, device string) string { return device + "|" + domain }

// Allocate returns the device's fake IP for domain. A live (unexpired)
// binding is never moved to another domain; when no address is free and
// none can be reclaimed from expiry, Allocate returns ErrPoolExhausted —
// the caller must shed load or grow the pool, never reuse live identity.
func (p *FakeIPPool) Allocate(domain, device string, generation uint64) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	k := p.key(domain, device)
	if addr, ok := p.byDomain[k]; ok {
		e := p.byAddr[addr]
		if e != nil && e.expires.After(now) {
			// refresh generation/ttl on reuse
			e.generation = generation
			e.expires = now.Add(p.ttl)
			return addr, nil
		}
		p.releaseLocked(addr)
	}
	// reclaim anything expired first
	p.reclaimExpiredLocked(now)
	if len(p.free) == 0 {
		return netip.Addr{}, ErrPoolExhausted
	}
	off := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	addr, err := offAddr(p.base, off)
	if err != nil || !p.base.Contains(addr) {
		// an out-of-range address is a pool invariant violation: put the
		// offset back and refuse rather than leak a foreign address
		p.free = append(p.free, off)
		return netip.Addr{}, fmt.Errorf("fake-ip pool %v: computed address outside prefix (internal error)", p.base)
	}
	p.byAddr[addr] = &fakeEntry{domain: domain, deviceID: device, generation: generation, expires: now.Add(p.ttl)}
	p.byDomain[k] = addr
	return addr, nil
}

func (p *FakeIPPool) reclaimExpiredLocked(now time.Time) {
	for addr, e := range p.byAddr {
		if !e.expires.After(now) {
			p.releaseLocked(addr)
		}
	}
}

// Lookup resolves a fake IP back to its domain. Expired entries are
// released on access: a stale mapping must never answer a flow (the
// destination would resolve through a dead scope).
func (p *FakeIPPool) Lookup(addr netip.Addr) (domain string, generation uint64, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.byAddr[addr]
	if e == nil {
		return "", 0, false
	}
	if !e.expires.After(p.now()) {
		p.releaseLocked(addr)
		return "", 0, false
	}
	return e.domain, e.generation, true
}

// ReleaseForDevice drops all mappings of one device (disconnect/revoke).
func (p *FakeIPPool) ReleaseForDevice(device string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for addr, e := range p.byAddr {
		if e.deviceID == device {
			p.releaseLocked(addr)
		}
	}
	_ = now
}

func (p *FakeIPPool) releaseLocked(addr netip.Addr) {
	e := p.byAddr[addr]
	if e == nil {
		return
	}
	delete(p.byAddr, addr)
	k := p.key(e.domain, e.deviceID)
	if cur, ok := p.byDomain[k]; ok && cur == addr {
		delete(p.byDomain, k)
	}
	// return the offset to the free list
	if off, ok := offsetOf(p.base, addr); ok {
		p.free = append(p.free, off)
	}
}

func offAddr(base netip.Prefix, off uint32) (netip.Addr, error) {
	addr := base.Addr()
	if addr.Is4() || addr.Is4In6() {
		a := addr.As4()
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		v += off
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
	}
	// v6: offset into the low 32 bits of a /64-style prefix host part
	a := addr.As16()
	lo := uint32(a[12])<<24 | uint32(a[13])<<16 | uint32(a[14])<<8 | uint32(a[15])
	lo += off
	a[12], a[13], a[14], a[15] = byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo)
	return netip.AddrFrom16(a), nil
}

// offsetOf returns the pool offset of addr within base (1-based), or
// false for addresses outside or at the base (network) address. 64-bit
// arithmetic: the v4 space does not fit signed 32-bit diffs safely.
func offsetOf(base netip.Prefix, addr netip.Addr) (uint32, bool) {
	if !addr.IsValid() || !base.IsValid() {
		return 0, false
	}
	a := base.Addr().Unmap()
	x := addr.Unmap()
	if a.Is4() != x.Is4() {
		return 0, false
	}
	var baseV, v uint64
	if a.Is4() {
		b := a.As4()
		baseV = uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		y := x.As4()
		v = uint64(y[0])<<24 | uint64(y[1])<<16 | uint64(y[2])<<8 | uint64(y[3])
	} else {
		b := a.As16()
		y := x.As16()
		for i := 0; i < 12; i++ {
			if b[i] != y[i] {
				return 0, false
			}
		}
		baseV = uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
		v = uint64(y[12])<<24 | uint64(y[13])<<16 | uint64(y[14])<<8 | uint64(y[15])
	}
	if v <= baseV || v-baseV > uint64(^uint32(0)-1) {
		return 0, false
	}
	return uint32(v - baseV), true
}

// RandomHex is a small helper for opaque tokens (batch/flow ids) so this
// package does not depend on a uuid library.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
