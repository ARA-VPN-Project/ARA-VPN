//go:build unix

package policy

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on path, serializing writers
// ACROSS PROCESSES (review R07: independent CLI invocations are separate
// processes; a mutex inside one object cannot protect them). Returns a
// release function. Darwin and Linux (the ARA targets) both support
// flock.
func lockFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	released := false
	return func() error {
		if released {
			return nil
		}
		released = true
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return err
	}, nil
}

// syncDir fsyncs a directory so a completed rename survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
