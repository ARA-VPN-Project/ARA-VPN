package qrencode

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// upstream encode + own render: the lab cross-check decodes the PNG with
// zbarimg (independent decoder) to prove interop.
func TestEncodeRenderStructure(t *testing.T) {
	m, err := Encode([]byte("https://ara.example/enroll#t123"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 21 || len(m[0]) != len(m) {
		t.Fatalf("bad matrix dims %d", len(m))
	}
	// finder top-left corner must be dark
	if !m[0][0] || !m[0][6] || !m[6][0] {
		t.Fatal("finder corner damaged")
	}
	// timing pattern alternates
	for i := 8; i < len(m)-8; i++ {
		if m[6][i] == m[6][i-1] {
			t.Fatalf("timing broken at %d", i)
		}
	}
	pngBytes, err := PNG(m, 4)
	if err != nil || len(pngBytes) < 100 || !bytes.HasPrefix(pngBytes, []byte("\x89PNG")) {
		t.Fatalf("png render: len=%d err=%v", len(pngBytes), err)
	}
	svg := SVG(m, 4)
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "path") {
		t.Fatal("svg render malformed")
	}
}

// TestRenderForZbar writes a PNG when QR_PNG is set; the lab cross-check
// decodes it with zbarimg (independent decoder).
func TestRenderForZbar(t *testing.T) {
	payload := os.Getenv("QR_PAYLOAD")
	out := os.Getenv("QR_PNG")
	if payload == "" || out == "" {
		t.Skip("no env")
	}
	m, err := Encode([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	b, err := PNG(m, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
