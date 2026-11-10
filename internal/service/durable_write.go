package service

// DurableFileWrite (B10): write→fsync(file)→rename→fsync(dir). Rename
// gives atomic visibility, fsync gives the claimed persistence; errors
// are returned so callers fail closed instead of pretending the state
// survived. Temp names are unique per call (concurrent writers never
// clobber each other's temps).
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func DurableFileWrite(path string, data []byte) error {
	return durableFileWrite(path, data, nil)
}

func durableFileWrite(path string, data []byte, prepare func(*os.File) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("durability: temp: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if prepare != nil {
		if err := prepare(f); err != nil {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("durability: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("durability: fsync file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("durability: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("durability: rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("durability: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("durability: fsync dir: %w", err)
	}
	return nil
}

// sha256Hex is a hex-digest helper for operation fingerprints.
func sha256HexStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
