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
type rootCredFiles struct {
	dir *service.TrustedDir
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
	return rootCredFiles{dir: d}, nil
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
	f, err := r.dir.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NONBLOCK, config.FileMode)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	unlock, err := config.LockOpenFile(f)
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
	return readCredentialFrom(f, ownedByThisUser)
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
	return r.dir.WriteFile(name, data, config.FileMode)
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
