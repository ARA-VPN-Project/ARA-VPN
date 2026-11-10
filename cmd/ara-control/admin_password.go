package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

type loginAttempt struct {
	failures int
	until    time.Time
}

type adminLoginState struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	changed  string
}

func loginAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// The local reverse proxy replaces client-supplied forwarding headers.
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if client, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return client.Unmap().String()
		}
	}
	return host
}

func (s *server) allowAdminLogin(r *http.Request, user, password string, now time.Time) bool {
	s.login.mu.Lock()
	defer s.login.mu.Unlock()
	if s.login.attempts == nil {
		s.login.attempts = map[string]loginAttempt{}
	}
	for ip, entry := range s.login.attempts {
		if !entry.until.After(now) {
			delete(s.login.attempts, ip)
		}
	}
	ip := loginAddress(r)
	entry, exists := s.login.attempts[ip]
	if entry.failures >= 5 || !exists && len(s.login.attempts) >= 4096 {
		return false
	}
	u, want := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(s.adminUsername))
	pass := s.adminPasswordMatches(password)
	if s.adminUsername != "" && pass && subtleCompare(string(u[:]), string(want[:])) == 1 {
		delete(s.login.attempts, ip)
		return true
	}
	entry.failures++
	if entry.failures == 1 || entry.failures == 5 {
		entry.until = now.Add(10 * time.Minute)
	}
	s.login.attempts[ip] = entry
	return false
}

func (s *server) adminPasswordMatches(password string) bool {
	if len(password) > 256 {
		return false
	}
	if s.login.changed == "" {
		a, b := sha256.Sum256([]byte(password)), sha256.Sum256([]byte(s.adminPassword))
		return s.adminPassword != "" && subtleCompare(string(a[:]), string(b[:])) == 1
	}
	b, err := hex.DecodeString(s.login.changed)
	if err != nil || len(b) != 48 {
		return false
	}
	hash, err := scrypt.Key([]byte(password), b[:16], 1<<15, 8, 1, 32)
	return err == nil && subtleCompare(string(hash), string(b[16:])) == 1
}

func writePrivateAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".private-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readChangedPassword(dir string) (string, error) {
	path := filepath.Join(dir, "admin.password-hash")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 96 {
		return "", errors.New("invalid admin password hash file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if _, err = hex.DecodeString(string(b)); err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *server) handleChangeAdminPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || len(req.New) < 14 || len(req.New) > 256 {
		http.Error(w, `{"error":"PASSWORD_REQUIREMENTS"}`, http.StatusBadRequest)
		return
	}
	s.login.mu.Lock()
	defer s.login.mu.Unlock()
	if !s.adminPasswordMatches(req.Current) {
		http.Error(w, `{"error":"AUTH_FAILED"}`, http.StatusUnauthorized)
		return
	}
	saltHex, err := randomHex(16)
	if err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	salt, _ := hex.DecodeString(saltHex)
	hash, err := scrypt.Key([]byte(req.New), salt, 1<<15, 8, 1, 32)
	if err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	encoded := saltHex + hex.EncodeToString(hash)
	if err = writePrivateAtomic(filepath.Join(s.stateDir, "admin.password-hash"), []byte(encoded)); err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	s.login.changed = encoded
	sessMu.Lock()
	clear(sessions)
	sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
}
