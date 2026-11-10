//go:build !unix

package policy

import "fmt"

// lockFile is unavailable off-UNIX: cross-process CAS cannot be promised,
// so writes refuse rather than race (review R07). The ARA targets
// (Debian, macOS) are UNIX and always take the real implementation.
func lockFile(path string) (func() error, error) {
	return nil, fmt.Errorf("cross-process locking unavailable on this platform; policy writes refused")
}

func syncDir(dir string) error { return nil }
