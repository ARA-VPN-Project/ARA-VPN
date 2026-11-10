package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aravpn/internal/service"
)

var adminPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_-]{1,80}$`)

func validateAdminPath(path string) error {
	if !adminPathPattern.MatchString(path) {
		return errors.New("admin path must be one URL segment with letters, digits, hyphens or underscores")
	}
	switch path {
	case "/api", "/sub", "/enroll", "/healthz":
		return errors.New("admin path is reserved")
	}
	return nil
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type adminAccess struct {
	path      string
	linkKey   string
	apiKey    string
	username  string
	password  string
	webSecret string
}

func initializeAdminAccess(dir, override string) (adminAccess, error) {
	var access adminAccess
	if override != "" {
		if err := validateAdminPath(override); err != nil {
			return access, err
		}
	}
	storedPath, err := privateValue(dir, "admin.path", "panel-", 16)
	if err != nil {
		return access, err
	}
	access.path = storedPath
	if override != "" {
		access.path = override
	}
	if err := validateAdminPath(access.path); err != nil {
		return access, err
	}
	if access.linkKey, err = privateValue(dir, "admin.link-key", "", 32); err != nil {
		return access, err
	}
	if decoded, err := hex.DecodeString(access.linkKey); err != nil || len(decoded) != 32 {
		return access, errors.New("invalid admin.link-key")
	}
	if access.apiKey, err = privateValue(dir, "control.token", "", 32); err != nil {
		return access, err
	}
	if len(access.apiKey) < 32 || subtleCompare(access.apiKey, access.linkKey) == 1 {
		return access, errors.New("invalid control.token")
	}
	for _, credential := range []struct {
		name   string
		size   int
		target *string
	}{
		{"admin.web-secret", 24, &access.webSecret},
		{"admin.username", 6, &access.username},
		{"admin.password", 24, &access.password},
	} {
		v, err := privateValue(dir, credential.name, "", credential.size)
		if err != nil {
			return access, err
		}
		decoded, err := hex.DecodeString(v)
		if err != nil || len(decoded) != credential.size {
			return access, fmt.Errorf("invalid %s", credential.name)
		}
		*credential.target = v
	}

	return access, nil
}

// privateValue publishes a fully written file without replacing an existing
// value, including when first startup overlaps with installer initialization.
func privateValue(dir, name, pathPrefix string, size int) (string, error) {
	path := filepath.Join(dir, name)
	read := func() (string, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 {
			return "", fmt.Errorf("%s must be a regular 0600 file", name)
		}
		value, err := os.ReadFile(path)
		return strings.TrimSpace(string(value)), err
	}
	if value, err := read(); !errors.Is(err, os.ErrNotExist) {
		return value, err
	}

	value, err := randomHex(size)
	if err != nil {
		return "", err
	}
	if pathPrefix != "" {
		value = "/" + pathPrefix + value
	}
	f, err := os.CreateTemp(dir, ".admin-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err = fmt.Fprintln(f, value); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err := os.Link(f.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return read()
		}
		return "", err
	}
	d, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer d.Close()
	return value, d.Sync()
}

func (a adminAccess) webPath() string { return a.path + "-" + a.webSecret }

func configuredAdminOrigin(dir, explicit string) (string, error) {
	origin := strings.TrimSpace(explicit)
	if origin == "" {
		b, err := os.ReadFile(filepath.Join(dir, "admin.origin"))
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		origin = strings.TrimSpace(string(b))
	}
	if origin == "" {
		return "", nil
	}
	return service.LinkOrigin(origin)
}
