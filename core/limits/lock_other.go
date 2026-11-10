//go:build !unix

package limits

import (
	"errors"
	"os"
)

func flockExclusive(f *os.File) error {
	_ = f
	return errors.New("journal locking unavailable on this platform")
}

func funlock(f *os.File) error {
	_ = f
	return nil
}
