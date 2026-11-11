package pii

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// KeyFileName is k_master's file in the engine's stateDir (decision M51-1).
const KeyFileName = "pii.key"

const (
	// keyFileMode: readable and writable by the engine's OS user only.
	keyFileMode os.FileMode = 0o600
	// keyFilePermMask is the permission bits the key file must not have:
	// anything for group or others, the same check as the credential file.
	keyFilePermMask os.FileMode = 0o077
)

// LoadKeys reads k_master from path and derives the keys. When the file is
// missing it creates it first with MasterKeySize bytes from random, mode 0600,
// without ever replacing a file that exists. It refuses a key file that is not
// a regular file, has the wrong size, or (outside Windows) a mode wider than
// 0600. Errors name the path, never key bytes.
func LoadKeys(path string, random io.Reader) (*Keys, error) {
	master, err := readOrCreateMaster(path, random)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	return NewKeys(master)
}

func readOrCreateMaster(path string, random io.Reader) ([]byte, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := createMaster(path, random); err != nil {
			return nil, err
		}
	}
	return readMaster(path)
}

// createMaster writes a fresh key to a temp file in the same directory and
// hard-links it into place, so the key appears whole or not at all and a key
// another process created first is kept (the link then fails with exist).
func createMaster(path string, random io.Reader) error {
	master := make([]byte, MasterKeySize)
	defer clear(master)
	if _, err := io.ReadFull(random, master); err != nil {
		return fmt.Errorf("pii key %s: read random bytes: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("pii key %s: %w", path, err)
	}
	defer os.Remove(tmp.Name()) // the key stays reachable only through path
	if err := writeKeyTemp(tmp, master); err != nil {
		return fmt.Errorf("pii key %s: %w", path, err)
	}
	err = os.Link(tmp.Name(), path)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pii key %s: %w", path, err)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		return fmt.Errorf("pii key %s: %w", path, err)
	}
	// The new name (and the temp name gone) survive a crash only once the
	// directory itself is on disk.
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("pii key %s: sync directory: %w", path, err)
	}
	return nil
}

func writeKeyTemp(tmp *os.File, master []byte) error {
	if err := tmp.Chmod(keyFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(master); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

// readMaster opens the key file without following a symlink and without
// blocking on a FIFO, and checks the opened file itself (not just the path):
// a regular file, owned by this process's user, mode 0600 or narrower, of the
// right size. A file swapped between the check and the read is refused.
func readMaster(path string) ([]byte, error) {
	link, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("pii key %s: %w", path, err)
	}
	if !link.Mode().IsRegular() {
		return nil, notRegular(path)
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("pii key %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("pii key %s: %w", path, err)
	}
	if !os.SameFile(link, fi) || !fi.Mode().IsRegular() {
		return nil, notRegular(path)
	}
	if err := checkOwner(fi); err != nil {
		return nil, fmt.Errorf("pii key %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&keyFilePermMask != 0 {
		return nil, fmt.Errorf("pii key %s is mode %o; it must be readable by the engine's user only (0600)", path, fi.Mode().Perm())
	}
	if fi.Size() != MasterKeySize {
		return nil, fmt.Errorf("pii key %s must hold %d bytes, found %d", path, MasterKeySize, fi.Size())
	}
	master := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(f, master); err != nil {
		clear(master)
		return nil, fmt.Errorf("pii key %s: %w", path, err)
	}
	return master, nil
}

func notRegular(path string) error {
	return fmt.Errorf("pii key %s must be a regular file, not a link or directory", path)
}
