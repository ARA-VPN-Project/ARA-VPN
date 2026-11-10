package main

// Static locks for the Control Center frontend invariants that the
// separate JavaScript DOM fixture
// executes against this file: B38 escaping of every external string before
// an innerHTML sink, and the B37 route editor reading/writing the
// canonical policy IR (cidr, ports ranges, capture of edited inputs).

import (
	"strings"
	"testing"
)

func TestPanelRenderNodesEscapesExternalStrings(t *testing.T) {
	src := (&server{}).panelPage("en")
	if !strings.Contains(src, "function esc(v)") {
		t.Fatal("esc helper missing")
	}
	i := strings.Index(src, "function renderNodes(")
	j := strings.Index(src, "// ---- route rule editor")
	if i < 0 || j < 0 || j < i {
		t.Fatal("renderNodes slice not found")
	}
	body := src[i:j]
	for _, want := range []string{"esc(n.id)", "esc(n.country)", "esc(n.role)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("renderNodes must escape %s (B38)", want)
		}
	}
}

func TestPanelRouteEditorUsesCanonicalIRAndCapturesInput(t *testing.T) {
	src := (&server{}).panelPage("en")
	i := strings.Index(src, "let DRAFT=null")
	j := strings.Index(src, "async function loadDiag()")
	if i < 0 || j < 0 || j < i {
		t.Fatal("editor slice not found")
	}
	body := src[i:j]
	// B37: canonical cidr rendered (not ip_cidr/ip_suffix)
	if !strings.Contains(body, "(r.cidr||[])") {
		t.Fatal("match column must render the canonical cidr field")
	}
	if strings.Contains(body, "ip_cidr") || strings.Contains(body, "ip_suffix") {
		t.Fatal("editor must not read non-canonical ip_cidr/ip_suffix fields")
	}
	// The detail form carries all canonical fields.
	for _, f := range []string{`data-f="id"`, `data-f="match"`, `data-f="proto"`, `data-f="ports"`, `data-f="action"`} {
		if !strings.Contains(body, f) {
			t.Fatalf("editor row must carry %s", f)
		}
	}
	// Changes enter the draft only after the detail form is validated.
	for _, want := range []string{"id:values.id.trim()", "next.domain_suffix.push", "next.cidr.push", "next.domain_exact.push", "proto:values.proto", "next.ports.push", "next.action=values.destination", "next.exit_id=values.destination.slice(5)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dDraft must capture edits: missing %s", want)
		}
	}
	// add/delete/reorder/toggle present
	for _, want := range []string{"function addRule(", "function editRule(", "candidate.rules.splice(Number(values.position)-1,0,next)", "enabled:values.enabled==='on'"} {
		if !strings.Contains(body, want) {
			t.Fatalf("editor action missing: %s", want)
		}
	}
}

func TestPanelNoUnescapedInterpolationInKnownSinks(t *testing.T) {
	src := (&server{}).panelPage("en")
	// renderSubs/devices/invites/audit external columns must go through esc
	for _, want := range []string{"esc(x.name)", "esc(d.name)", "esc(i.device_id)", "esc(e.actor)", "esc(e.action)", "msg.textContent=err.message", "esc(r.dest)"} {
		if !strings.Contains(src, want) {
			t.Fatalf("sink not escaped: %s", want)
		}
	}
}
