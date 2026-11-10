// Package qrencode renders invite links as QR module matrices. Encoding
// is delegated to the pinned upstream library rsc.io/qr (BSD-2-Clause,
// hash-locked in go.sum and third_party.lock.json) — a self-written codec
// was rejected after the lab cross-check found subtle spec bugs; the
// upstream implementation is the checked reference. This package adds the
// product-facing API (boolean matrix, PNG, SVG) on the standard library
// only.
package qrencode

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"

	qr "rsc.io/qr"
)

// Encode returns the module matrix for data (byte mode, error-correction
// level M, automatic version). true = dark module.
func Encode(data []byte) ([][]bool, error) {
	code, err := qr.Encode(string(data), qr.M)
	if err != nil {
		return nil, fmt.Errorf("qrencode: %w", err)
	}
	size := code.Size
	m := make([][]bool, size)
	for r := 0; r < size; r++ {
		m[r] = make([]bool, size)
		for c := 0; c < size; c++ {
			m[r][c] = code.Black(c, r)
		}
	}
	return m, nil
}

// PNG renders the matrix as a PNG with the given module scale and a
// 4-module quiet zone.
func PNG(m [][]bool, scale int) ([]byte, error) {
	if scale < 2 || scale > 64 {
		return nil, fmt.Errorf("qrencode: scale %d out of range", scale)
	}
	size := len(m)
	quiet := 4
	dim := (size + 2*quiet) * scale
	img := image.NewRGBA(image.Rect(0, 0, dim, dim))
	for y := 0; y < dim; y++ {
		for x := 0; x < dim; x++ {
			img.Set(x, y, color.White)
		}
	}
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if !m[r][c] {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.Set((c+quiet)*scale+dx, (r+quiet)*scale+dy, color.Black)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SVG renders the matrix as a vector SVG string (crisp at any zoom).
func SVG(m [][]bool, scale int) string {
	if scale < 2 {
		scale = 4
	}
	size := len(m)
	quiet := 4
	dim := (size + 2 * quiet) * scale
	var b strings.Builder
	fmt.Fprintf(&b, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" shape-rendering=\"crispEdges\">", dim, dim, dim, dim)
	fmt.Fprintf(&b, "<rect width=\"100%%\" height=\"100%%\" fill=\"#ffffff\"/>")
	fmt.Fprintf(&b, "<path fill=\"#000000\" d=\"")
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if !m[r][c] {
				continue
			}
			fmt.Fprintf(&b, "M%d %dh%dv%dh-%dz", (c+quiet)*scale, (r+quiet)*scale, scale, scale, scale)
		}
	}
	b.WriteString("\"/></svg>")
	return b.String()
}
