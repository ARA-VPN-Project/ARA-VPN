package nodebackup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineArchiveRoundTripAndConflict(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	contents := map[string]string{"etc/ara-edge/edge.json": "config", "var/lib/ara-control/control.db": "db", "var/lib/ara-control/admin.link-key": "secret"}
	for name, data := range contents {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "backup.tgz")
	if _, err := Create(src, archive); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archive); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(archive, dst); err != nil {
		t.Fatal(err)
	}
	for name, data := range contents {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(got) != data {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := Restore(archive, dst); err == nil {
		t.Fatal("overwrote existing state")
	}
	info, err := os.Stat(archive)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("archive is not private")
	}
	if err := os.Truncate(archive, info.Size()-3); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archive); err == nil {
		t.Fatal("accepted truncated archive")
	}
}
