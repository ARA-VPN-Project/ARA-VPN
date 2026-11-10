package main

// DurableFileWrite (B10): write→fsync(file)→rename→fsync(dir) with unique
// temps and returned errors; quota lease state fail-closes on error.
import (
	"fmt"
	"os"
	"path/filepath"
)

func durableFileWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("durability: temp: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
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
