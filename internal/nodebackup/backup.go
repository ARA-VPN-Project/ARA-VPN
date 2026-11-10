// Package nodebackup implements offline archives of the native ARA state.
package nodebackup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var paths = []string{"etc/ara", "etc/ara-edge", "etc/default/ara-control", "var/lib/ara-agent", "var/lib/ara-control", "var/lib/ara-edge"}

const maxBytes int64 = 8 << 30
const maxEntries = 100000

type Result struct {
	Paths []string `json:"paths"`
	Files int      `json:"files"`
	Bytes int64    `json:"bytes"`
}

func ownRoot(name string) string {
	if !filepath.IsLocal(name) || strings.Contains(name, "\\") || path.Clean(name) != name {
		return ""
	}
	for _, root := range paths {
		if name == root || strings.HasPrefix(name, root+"/") {
			return root
		}
	}
	return ""
}

// Create writes a private archive. Callers must quiesce all ARA writers.
func Create(root, out string) (result Result, err error) {
	root, err = filepath.Abs(root)
	if err != nil {
		return result, err
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return result, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return result, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return result, err
	}
	if rel, e := filepath.Rel(root, filepath.Join(parent, filepath.Base(out))); e == nil && ownRoot(rel) != "" {
		return result, fmt.Errorf("backup destination must be outside ARA state")
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, err
	}
	defer func() {
		f.Close()
		if err != nil {
			_ = os.Remove(out)
		}
	}()
	g := gzip.NewWriter(f)
	w := tar.NewWriter(g)
	entries := 0
	for _, name := range paths {
		start := filepath.Join(root, name)
		if _, err := os.Lstat(start); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return result, err
		}
		actual, err := filepath.EvalSymlinks(start)
		if err != nil || actual != start {
			return result, fmt.Errorf("unsupported symlink in ARA state path %s", name)
		}
		result.Paths = append(result.Paths, name)
		err = filepath.WalkDir(start, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				if info.Mode()&os.ModeSocket != 0 {
					return nil
				}
				return fmt.Errorf("unsupported entry %s", p)
			}
			entries++
			if entries > maxEntries || info.Size() > maxBytes-result.Bytes {
				return fmt.Errorf("archive size limit exceeded")
			}
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			h.Name, err = filepath.Rel(root, p)
			if err != nil {
				return err
			}
			h.Mode &= 0777
			if err := w.WriteHeader(h); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			file, err := os.Open(p)
			if err != nil {
				return err
			}
			defer file.Close()
			if _, err := io.CopyN(w, file, info.Size()); err != nil {
				return err
			}
			result.Files++
			result.Bytes += info.Size()
			return nil
		})
		if err != nil {
			return result, err
		}
	}
	if len(result.Paths) == 0 {
		return result, fmt.Errorf("ARA state was not found")
	}
	if err = w.Close(); err != nil {
		return result, err
	}
	if err = g.Close(); err != nil {
		return result, err
	}
	if err = f.Sync(); err != nil {
		return result, err
	}
	err = f.Close()
	return result, err
}

func inspect(archive string, materialize func(*tar.Header, io.Reader) error) (Result, error) {
	var result Result
	file, err := os.Open(archive)
	if err != nil {
		return result, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return result, err
	}
	defer reader.Close()
	t := tar.NewReader(reader)
	seen := map[string]byte{}
	for {
		h, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}
		root := ownRoot(h.Name)
		if root == "" || seen[h.Name] != 0 || len(seen) >= maxEntries || h.Size < 0 || h.Size > maxBytes-result.Bytes ||
			(h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg) || h.Mode&^0777 != 0 {
			return result, fmt.Errorf("invalid archive entry")
		}
		if root != h.Name && seen[path.Dir(h.Name)] != tar.TypeDir {
			return result, fmt.Errorf("archive entry has no parent")
		}
		if root == h.Name {
			if (root == "etc/default/ara-control") != (h.Typeflag == tar.TypeReg) {
				return result, fmt.Errorf("invalid ARA root entry")
			}
			result.Paths = append(result.Paths, root)
		}
		seen[h.Name] = h.Typeflag
		if h.Typeflag == tar.TypeReg {
			result.Files++
			result.Bytes += h.Size
		}
		if materialize != nil {
			if err := materialize(h, t); err != nil {
				return result, err
			}
		}
		if _, err := io.Copy(io.Discard, t); err != nil {
			return result, err
		}
	}
	if n, err := io.Copy(io.Discard, io.LimitReader(reader, 1)); err != nil || n != 0 {
		return result, fmt.Errorf("archive checksum or trailing data is invalid")
	}
	if len(result.Paths) == 0 {
		return result, fmt.Errorf("empty ARA archive")
	}
	return result, nil
}

func Verify(archive string) (Result, error) { return inspect(archive, nil) }

// Restore validates the archive in private staging and publishes only to
// absent ARA paths. Root-level restores remap service ownership by name.
func Restore(archive, root string) (Result, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Result{}, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	stage, err := os.MkdirTemp(root, ".ara-restore-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(stage)
	type directory struct {
		p      string
		header tar.Header
	}
	var directories []directory
	setMetadata := func(p string, h *tar.Header) error {
		if root == "/" {
			uid, gid, err := nativeOwner(h)
			if err != nil {
				return err
			}
			if err := os.Chown(p, uid, gid); err != nil {
				return err
			}
		}
		return os.Chmod(p, os.FileMode(h.Mode))
	}
	result, err := inspect(archive, func(h *tar.Header, r io.Reader) error {
		dest := filepath.Join(stage, h.Name)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.Mkdir(dest, 0700); err != nil {
				return err
			}
			directories = append(directories, directory{dest, *h})
			return nil
		}
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		err = errors.Join(copyErr, f.Sync(), f.Close())
		if err != nil {
			return err
		}
		return setMetadata(dest, h)
	})
	if err != nil {
		return result, err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := setMetadata(directories[i].p, &directories[i].header); err != nil {
			return result, err
		}
	}
	for _, name := range result.Paths {
		dest := filepath.Join(root, name)
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			return result, fmt.Errorf("restore destination already exists or cannot be read: %s", dest)
		}
		if err := ensureParents(root, filepath.Dir(dest)); err != nil {
			return result, err
		}
	}
	var published []string
	for _, name := range result.Paths {
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(root, name)); err != nil {
			for i := len(published) - 1; i >= 0; i-- {
				n := published[i]
				err = errors.Join(err, os.Rename(filepath.Join(root, n), filepath.Join(stage, n)))
			}
			return result, err
		}
		published = append(published, name)
	}
	return result, nil
}

func ensureParents(root, parent string) error {
	rel, err := filepath.Rel(root, parent)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("invalid restore parent: %s", parent)
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0755); err != nil {
				return err
			}
		} else if err != nil || !info.IsDir() {
			return fmt.Errorf("restore parent is not an ordinary directory: %s", current)
		}
	}
	return nil
}

func nativeOwner(h *tar.Header) (int, int, error) {
	allowed := func(s string) bool { return s == "root" || s == "ara-agent" || s == "ara-edge" || s == "ara-control" }
	if !allowed(h.Uname) || !allowed(h.Gname) {
		return 0, 0, fmt.Errorf("unsupported native owner for %s", h.Name)
	}
	u, err := user.Lookup(h.Uname)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(h.Gname)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	return uid, gid, err
}
