// Command ara-testpoint is the authenticated speed-test endpoint for ARA
// nodes (docs/SPEEDTEST.md): three typed endpoints (download, upload,
// echo) behind bearer tokens, clamped budgets, a concurrency cap and
// nothing else — no URL fetching, no relay, no shell. It binds an
// explicitly given address; production deployments bind it to the
// node-private address reachable only through the tunnel or the lab LAN.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"aravpn/core/speedtest"
)

func main() {
	listen := flag.String("listen", "", "bind host:port (explicit, private by convention)")
	tokensFile := flag.String("tokens", "", "file with one bearer token per line (0600)")
	maxBytes := flag.Int64("max-bytes", speedtest.DefaultMaxBytesPerStream, "per-stream byte cap")
	maxSeconds := flag.Int("max-seconds", int(speedtest.DefaultMaxStreamDuration.Seconds()), "per-stream duration cap")
	maxConcurrent := flag.Int("max-concurrent", speedtest.DefaultMaxConcurrent, "concurrent stream cap")
	flag.Parse()
	if *listen == "" || *tokensFile == "" {
		log.Fatal("usage: ara-testpoint -listen host:port -tokens tokens.file")
	}
	b, err := os.ReadFile(*tokensFile)
	if err != nil {
		log.Fatalf("tokens: %v", err)
	}
	var tokens []string
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		log.Fatal("tokens file is empty: an endpoint without tokens refuses everything (by design)")
	}
	s := speedtest.NewServer(tokens)
	s.MaxBytesPerStream = *maxBytes
	s.MaxStreamDuration = time.Duration(*maxSeconds) * time.Second
	s.MaxConcurrent = *maxConcurrent
	s.OnRequest = func(direction string, requested, granted int64) {
		log.Printf("stream %s requested=%d granted=%d", direction, requested, granted)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	// refuse anything but the typed endpoints with a hard 404 (default mux
	// behavior) and cap header size via Server settings
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       0, // streams are long; per-request deadlines set in handlers
		WriteTimeout:      0,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    speedtest.MaxHeaderBytes,
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("ara-testpoint on %s (%d tokens, caps: %d MiB/stream, %ds, %d concurrent)",
		*listen, len(tokens), *maxBytes/(1<<20), *maxSeconds, *maxConcurrent)
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
	_ = fmt.Sprint
}
