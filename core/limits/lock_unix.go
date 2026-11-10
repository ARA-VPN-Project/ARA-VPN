//go:build unix

package limits

import (
	"os"
	"syscall"
)

// flockExclusive/funlock serialize journal writers and the legacy
// migration across processes (review V04/V06-adjacent: whole-operation
// serialization, not per-append).
func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func funlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
