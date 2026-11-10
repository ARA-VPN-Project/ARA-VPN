// fileserver is a tiny static file server for lab canaries. Usage:
//   fileserver <listen-addr> <dir>
// Example (inside a lab netns): fileserver 10.72.1.1:8000 /tmp/ara-canary-f
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fileserver <listen-addr> <dir>")
		os.Exit(2)
	}
	addr, dir := os.Args[1], os.Args[2]
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(dir)))
	// PUT/POST /upload: bounded sink that returns the received byte count
	// and sha256 — for end-to-end upload integrity and rate checks.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "sha256=%s bytes=%d\n", hex.EncodeToString(h.Sum(nil)), n)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Println("serving", dir, "on", addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "err:", err)
		os.Exit(1)
	}
}

