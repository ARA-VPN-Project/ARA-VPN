//go:build !unix

package txlog

import (
	"errors"
	"os"
)

// flock is unavailable off-UNIX: appends are serialized per-process only.
// The ARA targets (Debian, macOS) always take the real implementation.
func flockExclusive(f *os.File) error { return errors.New("flock unavailable") }

func funlock(f *os.File) error {
	_ = f
	return nil
}
