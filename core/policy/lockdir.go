package policy

import "path/filepath"

// LockDir takes the directory's cross-process writer lock (review T06):
// a whole read→precondition→effect→identity transaction must hold it, not
// just a single file append. Used by both the policy store and the limits
// state directory.
func LockDir(dir string) (func() error, error) {
	return lockFile(filepath.Join(dir, ".writer.lock"))
}
