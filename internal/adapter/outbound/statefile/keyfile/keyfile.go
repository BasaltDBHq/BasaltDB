// Package keyfile keeps the engine's channel keys (channel.EngineKeys) in
// <stateDir>/channel.json (CONTRACT.md, Vault channel, Engine keys). It
// refuses a file, or a directory, someone else could have changed: the
// content checks are channel.ParseKeyFile's.
package keyfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

const (
	// keyFileMode: readable and writable by the engine's OS user only.
	keyFileMode os.FileMode = channel.KeyFileMode
	// keyFilePermMask is the bits the file must not have: anything for group
	// or others, as the credential and links files.
	keyFilePermMask os.FileMode = 0o077
	// dirWritableMask is the write bits for group and others.
	dirWritableMask os.FileMode = 0o022
	// keyFileMax bounds what is read; a valid file is well under 1 KiB.
	keyFileMax = channel.KeyFileMax
	// goosWindows is runtime.GOOS on Windows, where modes are not checked.
	goosWindows = "windows"
)

// checkStateDir refuses a key file's directory unless it is a directory
// (not a link to one) owned by the engine's user that neither group nor
// others can write: whoever can write it can swap the key file.
func checkStateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory: %w", reason(err))
	}
	return checkStateDirInfo(fi)
}

func checkStateDirInfo(fi os.FileInfo) error {
	if !fi.IsDir() {
		return errors.New("the state directory must be a directory, not a link")
	}
	if runtime.GOOS == goosWindows {
		return nil
	}
	if err := checkOwner(fi); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if fi.Mode().Perm()&dirWritableMask != 0 {
		return fmt.Errorf("state directory is mode %o; group and others must not be able to write it", fi.Mode().Perm())
	}
	return nil
}

// staleTempAge is how old a leftover temporary key file must be before a
// start removes it, so a concurrent first start's file is left alone.
const staleTempAge = time.Minute

// removeStaleTemps removes leftover <name>.*.tmp files of a crashed first
// start: regular files this user owns, older than staleTempAge. Best effort;
// a failure here changes nothing about the key file.
func removeStaleTemps(path string, now func() time.Time) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), globEscape(filepath.Base(path))+".*.tmp"))
	if err != nil {
		return
	}
	for _, m := range matches {
		fi, err := os.Lstat(m)
		if err != nil || !fi.Mode().IsRegular() || checkOwner(fi) != nil || now().Sub(fi.ModTime()) < staleTempAge {
			continue
		}
		_ = os.Remove(m)
	}
}

// globEscape quotes the glob metacharacters of a file name.
func globEscape(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(`*?[\`, r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// reason drops the path a *fs.PathError repeats.
func reason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func keyFileErr(path, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", channel.ErrKeyFile, path, fmt.Sprintf(format, args...))
}

// LoadOrCreateKeys returns the engine's keys from path, creating the file
// with fresh keys when it does not exist (CONTRACT.md, Vault channel, Engine
// keys: made on the engine's first start, whatever vault says). A file that
// exists is never replaced: one in a directory another user owns or others
// can write, one that is not a regular file, belongs to another user, grants
// group or other access, cannot be read, fails the schema, whose engineId is not its signing key's or whose
// boxKeySig does not verify is refused with channel.ErrKeyFile and left untouched.
func LoadOrCreateKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	if err := checkStateDir(filepath.Dir(path)); err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	removeStaleTemps(path, now)
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := createKeyFile(path, now); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, keyFileErr(path, "%v", reason(err))
	}
	return LoadKeys(path)
}

// LoadKeys reads and checks an existing key file. It never writes.
func LoadKeys(path string) (*channel.EngineKeys, error) {
	raw, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return channel.ParseKeyFile(path, raw)
}

// createKeyFile writes fresh keys to a temporary file in the same directory
// (mode 0600, fsync) and hard-links it to path, so the file appears whole or
// not at all, and a file another process created first is kept: the link
// then fails with "exists" and that file is loaded instead.
func createKeyFile(path string, now func() time.Time) error {
	raw, _, err := channel.NewKeyFile(now)
	if err != nil {
		return keyFileErr(path, "make keys: %v", err)
	}
	defer clear(raw)
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return keyFileErr(path, "%v", err)
	}
	defer os.Remove(tmp.Name()) // the keys stay reachable only through path
	if err := writeTemp(tmp, raw); err != nil {
		return keyFileErr(path, "%v", err)
	}
	err = os.Link(tmp.Name(), path)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return keyFileErr(path, "%v", err)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		return keyFileErr(path, "%v", err)
	}
	// The new name (and the temporary one gone) survive a crash only once
	// the directory itself is on disk.
	if err := syncDir(dir); err != nil {
		return keyFileErr(path, "sync directory: %v", err)
	}
	return nil
}

func writeTemp(tmp *os.File, raw []byte) error {
	if err := tmp.Chmod(keyFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

// readKeyFile opens path without following a symlink and without blocking
// on a FIFO, after checking its directory (checkStateDir), and checks the
// opened file itself, not only the path: a regular file owned by this
// process's user, mode 0600 or narrower, of a sane size. A file swapped between the checks and the read is refused.
func readKeyFile(path string) ([]byte, error) {
	if err := checkStateDir(filepath.Dir(path)); err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	link, err := os.Lstat(path)
	if err != nil {
		return nil, keyFileErr(path, "%v", reason(err))
	}
	if !link.Mode().IsRegular() {
		return nil, keyFileErr(path, "must be a regular file, not a link or directory")
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, keyFileErr(path, "%v", reason(err))
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	if !os.SameFile(link, fi) || !fi.Mode().IsRegular() {
		return nil, keyFileErr(path, "must be a regular file, not a link or directory")
	}
	if err := checkOwner(fi); err != nil {
		return nil, keyFileErr(path, "%v", err)
	}
	if runtime.GOOS != goosWindows && fi.Mode().Perm()&keyFilePermMask != 0 {
		return nil, keyFileErr(path, "mode is %o; it must be readable by the engine's user only (0600)", fi.Mode().Perm())
	}
	if fi.Size() > keyFileMax {
		return nil, keyFileErr(path, "%d bytes is too large for a key file", fi.Size())
	}
	// One buffer of the size Stat gave, plus a byte to notice growth, so
	// reading leaves no grown copies behind.
	raw := make([]byte, fi.Size()+1)
	n, err := io.ReadFull(f, raw)
	if !errors.Is(err, io.ErrUnexpectedEOF) || int64(n) != fi.Size() {
		clear(raw)
		if err == nil {
			return nil, keyFileErr(path, "changed while it was read")
		}
		return nil, keyFileErr(path, "%v", err)
	}
	return raw[:n], nil
}
