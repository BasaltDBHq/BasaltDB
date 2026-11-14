//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// rootCredFiles reaches init --remote's credential files as root. The config
// directory may belong to the engine's user, who could swap agents/ for a
// symlink to send root's reads and writes elsewhere, so agents/ is opened
// once from / without following a link (service.OpenTrustedDir: every
// directory on the way owned by root or the config directory's owner, not
// writable by group or others) and every file is then reached relative to
// it, never by path.
//
// The files belong to the engine's user, the owner of agents/ read from its
// open descriptor (the same rule as the lock files): root hands every file
// it writes, and the lock file, to that owner, so the engine can read its
// credential and promote a .pending one. Root reads files owned by root or
// that owner. In a root-owned agents/ the files stay root's.
type rootCredFiles struct {
	dir *service.TrustedDir
	// owner gets the files root writes; -1 when agents/ is root's.
	owner int
}

// openRootCredFiles opens dir, the agents directory, as root, making it
// (and the config directory) when missing. The trusted owner is the config
// directory's, or, when it does not exist yet, that of the nearest
// directory above it that does.
func openRootCredFiles(dir string) (credFiles, error) {
	trusted, err := existingOwner(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
	d, err := service.OpenTrustedDir(dir, trusted, true)
	if err != nil {
		return nil, fmt.Errorf("the credential directory %s is refused: %w", dir, err)
	}
	dirUID, err := d.Owner()
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return rootCredFiles{dir: d, owner: credentialOwner(dirUID)}, nil
}

// credentialOwner is who gets the credential files root writes in a
// directory dirUID owns: that owner, never root (-1: keep root's).
func credentialOwner(dirUID int) int {
	if dirUID <= 0 {
		return -1
	}
	return dirUID
}

// ownedBy accepts a credential file owned by this process's user or by the
// directory's owner, the engine's user root hands them to.
func (r rootCredFiles) ownedBy(uid uint32) (bool, string) {
	if ok, _ := ownedByThisUser(uid); ok || (r.owner >= 0 && uint64(uid) == uint64(r.owner)) {
		return true, ""
	}
	if r.owner < 0 {
		return false, "root"
	}
	return false, fmt.Sprintf("root or uid %d (the owner of %s)", r.owner, r.dir.Path())
}

// existingOwner is the owner of path or, when it does not exist, of the
// nearest directory above it that does, not following a link.
func existingOwner(path string) (int, error) {
	for {
		fi, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) && filepath.Dir(path) != path {
			path = filepath.Dir(path)
			continue
		}
		if err != nil {
			return 0, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, errors.New("cannot read the directory's owner")
		}
		return int(st.Uid), nil
	}
}

// name is path's file name, refusing a path outside the opened directory.
func (r rootCredFiles) name(path string) (string, error) {
	if filepath.Dir(path) != r.dir.Path() {
		return "", fmt.Errorf("%s is not in %s", path, r.dir.Path())
	}
	return filepath.Base(path), nil
}

func (r rootCredFiles) lock(path string) (func(), error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	dirUID, err := r.dir.Owner()
	if err != nil {
		return nil, err
	}
	f, err := r.dir.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NONBLOCK, config.FileMode)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	// A lock file root makes, or finds root's, goes to agents/' owner (the
	// engine's user), as config.LockFile does, so the engine can open it.
	unlock, err := config.LockOpenFile(f, dirUID)
	if errors.Is(err, config.ErrLocked) {
		return nil, fmt.Errorf("another basalt init --remote is running for this agent, or the engine is finishing its setup (%s is locked); run it again in a moment", path)
	}
	return unlock, err
}

func (r rootCredFiles) open(path string) (*os.File, error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	return r.dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func (r rootCredFiles) read(path string) (string, os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	return readCredentialFrom(f, r.ownedBy)
}

func (r rootCredFiles) stat(path string) (os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func (r rootCredFiles) write(path string, data []byte) error {
	name, err := r.name(path)
	if err != nil {
		return err
	}
	return r.dir.WriteFile(name, data, config.FileMode, r.owner)
}

func (r rootCredFiles) rename(from, to string) error {
	a, err := r.name(from)
	if err != nil {
		return err
	}
	b, err := r.name(to)
	if err != nil {
		return err
	}
	return r.dir.Rename(a, b)
}

func (r rootCredFiles) close() { _ = r.dir.Close() }
