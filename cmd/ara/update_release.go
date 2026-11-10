package main

import (
	"archive/zip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aravpn/core/policy"
	"aravpn/core/update"
	"aravpn/internal/service"
)

const (
	maxReleaseBytes    = 160 << 20
	maxReleasePackage  = 48 << 20
	maxReleaseMetadata = 1 << 20
)

var releaseRoles = []string{update.RoleFileRoot, update.RoleFileTimestamp, update.RoleFileSnapshot, update.RoleFileTargets}

func validReleaseURL(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}

func fetchRelease(client *http.Client, rawURL, dest string) error {
	u, err := url.Parse(rawURL)
	if err != nil || !validReleaseURL(u) {
		return fmt.Errorf("release URL must be an HTTPS asset link without credentials or fragment")
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// GitHub Releases redirects downloads to its asset CDN.
		if len(via) >= 5 || !validReleaseURL(req.URL) {
			return fmt.Errorf("unsafe release redirect")
		}
		return nil
	}
	resp, err := c.Get(u.String())
	if err != nil {
		return fmt.Errorf("release download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release download: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxReleaseBytes {
		return fmt.Errorf("release exceeds download limit")
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxReleaseBytes+1))
	closeErr := f.Close()
	if err != nil || n > maxReleaseBytes {
		return fmt.Errorf("release is incomplete or exceeds download limit")
	}
	return closeErr
}

func readReleaseEntry(f *zip.File, limit int64) ([]byte, error) {
	if f == nil || !f.Mode().IsRegular() || f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("missing or oversized release entry")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("invalid release entry")
	}
	return data, nil
}

func stageReleaseZip(svc *service.Service, archive, dir string, roots []string, sel update.Selector, installed map[string]string, run updateRunner) ([]string, string, error) {
	z, err := zip.OpenReader(archive)
	if err != nil {
		return nil, "", fmt.Errorf("expected a signed ARA release ZIP")
	}
	defer z.Close()
	if len(z.File) > 64 {
		return nil, "", fmt.Errorf("too many release entries")
	}
	files := make(map[string]*zip.File, len(z.File))
	for _, f := range z.File {
		if !filepath.IsLocal(f.Name) || filepath.Base(f.Name) != f.Name || strings.ContainsAny(f.Name, "\\:") || files[f.Name] != nil || !f.Mode().IsRegular() {
			return nil, "", fmt.Errorf("invalid or duplicate release entry")
		}
		files[f.Name] = f
	}
	for _, name := range releaseRoles {
		data, err := readReleaseEntry(files[name], maxReleaseMetadata)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, "", err
		}
	}
	var paths []string
	var version string
	for _, component := range araComponents {
		current, ok := installed[component]
		if !ok {
			continue
		}
		sel.Component = component
		t, _, err := svc.UpdateCheckTUF(dir, roots, sel, "")
		if err != nil {
			return nil, "", err
		}
		name := t.URL
		if t.Format != "deb" || t.Length <= 0 || t.Length > maxReleasePackage || !strings.HasSuffix(name, ".deb") || componentOfArtifact(name) != component {
			return nil, "", fmt.Errorf("invalid signed package target for %s", component)
		}
		if version != "" && version != t.Version {
			return nil, "", fmt.Errorf("installed components require a single signed release version")
		}
		version = t.Version
		data, err := readReleaseEntry(files[name], t.Length)
		if err != nil || int64(len(data)) != t.Length || fmt.Sprintf("%x", sha256.Sum256(data)) != t.SHA256 {
			return nil, "", fmt.Errorf("signed package length or hash mismatch for %s", component)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, "", err
		}
		for field, expected := range map[string]string{"Package": component, "Version": version, "Architecture": t.Arch} {
			value, err := run("dpkg-deb", "--field", path, field)
			if err != nil || strings.TrimSpace(value) != expected {
				return nil, "", fmt.Errorf("package %s does not match signed %s", component, field)
			}
		}
		if _, err := run("dpkg", "--compare-versions", version, "ge", current); err != nil {
			return nil, "", fmt.Errorf("package downgrade refused for %s", component)
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, "", fmt.Errorf("no installed ARA Debian packages")
	}
	return paths, version, nil
}

func installedReleaseComponents(run updateRunner) (map[string]string, error) {
	installed := make(map[string]string)
	for _, component := range araComponents {
		out, err := run("dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", component)
		if err != nil {
			continue
		}
		fields := strings.Fields(out)
		if len(fields) == 2 && fields[0] == "installed" {
			installed[component] = fields[1]
		} else if len(fields) != 2 || (fields[0] != "config-files" && fields[0] != "not-installed") {
			return nil, fmt.Errorf("package %s has pending dpkg state", component)
		}
	}
	return installed, nil
}

func updateFromRelease(svc *service.Service, rawURL string, roots []string, sel update.Selector, install bool) (string, error) {
	if install && os.Geteuid() != 0 {
		return "", fmt.Errorf("package installation requires root")
	}
	base := filepath.Join(svc.State.Root, "updates", "release")
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	unlock, err := policy.LockDir(base)
	if err != nil {
		return "", err
	}
	defer unlock()
	installed, err := installedReleaseComponents(realRunner)
	if err != nil {
		return "", err
	}
	if len(installed) == 0 {
		return "", fmt.Errorf("no installed ARA Debian packages")
	}
	dir, err := os.MkdirTemp(base, "download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	archive := filepath.Join(dir, "release.zip")
	if err := fetchRelease(&http.Client{Timeout: 3 * time.Minute}, rawURL, archive); err != nil {
		return "", err
	}
	paths, version, err := stageReleaseZip(svc, archive, dir, roots, sel, installed, realRunner)
	if err != nil || !install {
		return version, err
	}
	// Anchor the common metadata only after every installed component is verified.
	sel.Component = componentOfArtifact(paths[0])
	if err := svc.AnchorTUF(dir, roots, sel); err != nil {
		return "", err
	}
	// Restart only units that were running before the upgrade.
	active := map[string]bool{}
	for _, unit := range []string{"ara-agent.service", "ara-edge.service", "ara-control.service"} {
		_, err := realRunner("systemctl", "is-active", "--quiet", unit)
		active[unit] = err == nil
	}
	run := func(name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) == 2 && args[0] == "list-unit-files" && !active[args[1]] {
			return "", fmt.Errorf("unit was inactive before update")
		}
		return realRunner(name, args...)
	}
	_, err = updateApplyBundle(svc, paths, run)
	return version, err
}
