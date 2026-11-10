package capability

import "testing"

func TestRequireAndUnsupported(t *testing.T) {
	node := Set{CapTUN: "1", CapTransportXHTTP: "1", CapIPv6: "1"}

	if err := node.Require(Set{CapTUN: "1", CapIPv6: "1"}); err != nil {
		t.Fatalf("supported set refused: %v", err)
	}
	err := node.Require(Set{CapTransportREALITY: "1"})
	ue, ok := err.(*UnsupportedError)
	if !ok {
		t.Fatalf("typed error expected, got %T: %v", err, err)
	}
	if ue.Capability != CapTransportREALITY {
		t.Fatalf("wrong capability named: %+v", ue)
	}

	err = node.Require(Set{CapTUN: "2"})
	if err == nil {
		t.Fatal("version mismatch accepted")
	}
	if _, ok := err.(*UnsupportedError); !ok {
		t.Fatalf("version mismatch must be typed: %v", err)
	}
}

func TestEmptyConstraintMatchesAnyVersion(t *testing.T) {
	node := Set{CapTUN: "9"}
	if err := node.Require(Set{CapTUN: ""}); err != nil {
		t.Fatalf("empty requirement should match any advertised version: %v", err)
	}
}

func TestCommonIntersection(t *testing.T) {
	a := Set{CapTUN: "1", CapIPv6: "1", CapQUOTA: "1"}
	b := Set{CapTUN: "1", CapIPv6: "0"}
	c := Common(a, b)
	if len(c) != 1 || c[CapTUN] != "1" {
		t.Fatalf("intersection: %v", c)
	}
}

func TestRenderStable(t *testing.T) {
	s := Set{CapIPv6: "1", CapTUN: ""}
	if Render := s.Render(); Render != "ipv6@1,tun" {
		t.Fatalf("render: %q", Render)
	}
}
