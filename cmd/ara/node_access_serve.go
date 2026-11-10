package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"aravpn/core/nodeaccess"
)

func serveNodeAccess() error {
	if os.Geteuid() != 0 || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return fmt.Errorf("node access helper requires its systemd socket")
	}
	config, err := os.Open("/etc/ara/node-access.json")
	if err != nil {
		return err
	}
	defer config.Close()
	info, err := config.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Size() > 64<<10 {
		return fmt.Errorf("node access policy must be a regular root-owned file (max 64 KiB)")
	}
	var entries []nodeaccess.Input
	decoder := json.NewDecoder(config)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return err
	}
	allowed := map[string]nodeaccess.Plan{}
	for _, entry := range entries {
		plan, err := nodeaccess.Build(entry)
		if err != nil {
			return fmt.Errorf("invalid node access policy: %w", err)
		}
		allowed[plan.Tag] = plan
	}
	socket := os.NewFile(3, "ara-node-access.socket")
	listener, err := net.FileListener(socket)
	socket.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	if listener.Addr().Network() != "unix" {
		return fmt.Errorf("node access helper requires a Unix socket")
	}
	server := http.Server{
		Handler:     nodeAccessHandler(allowed, applyNodeAccess),
		ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 4096,
	}
	return server.Serve(listener)
}

func nodeAccessHandler(allowed map[string]nodeaccess.Plan, apply func(nodeaccess.Plan, bool) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || (r.URL.Path != "/apply" && r.URL.Path != "/remove") {
			http.NotFound(w, r)
			return
		}
		var in nodeaccess.Input
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requested, err := nodeaccess.Build(in)
		plan, allowedRule := allowed[requested.Tag]
		if err != nil || !allowedRule || requested.Rule != plan.Rule {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := apply(plan, r.URL.Path == "/remove"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
