//go:build unix

package credfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// RootCredFiles reaches init --remote's credential files as root. The config
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
type RootCredFiles struct {
	dir TrustedDir
	// owner gets the files root writes; -1 when agents/ is root's.
	owner int
	// self is this process's uid: a file it does not own is checked with
	// pgdial.CheckForeignDSN.
	self int
}

// OpenRootCredFiles opens dir, the agents directory, as root, making it
// (and the config directory) when missing, through h. trusted is
// RootTrustedOwner's.
func OpenRootCredFiles(h FilesHost, dir string, trusted int) (Files, error) {
	d, err := h.OSOpenTrustedDir(dir, trusted, true)
	if err != nil {
		return nil, fmt.Errorf("the credential directory %s is refused: %w", dir, err)
	}
	dirUID, err := d.Owner()
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return RootCredFiles{dir: d, owner: CredentialOwner(dirUID), self: os.Geteuid()}, nil
}

// CredentialOwner is who gets the credential files root writes in a
// directory dirUID owns: that owner, never root (-1: keep root's).
func CredentialOwner(dirUID int) int {
	if dirUID <= 0 {
		return -1
	}
	return dirUID
}

// rules accept a credential file owned by this process's user or by the
// directory's owner, the engine's user root hands them to.
func (r RootCredFiles) rules() ownerfile.Rules {
	want := "root"
	if r.owner >= 0 {
		want = fmt.Sprintf("root or uid %d (the owner of %s)", r.owner, r.dir.Path())
	}
	return ownerfile.Rules{Owners: []int{r.self, r.owner}, OwnerName: want, MaxBytes: MaxCredentialBytes}
}

// name is path's file name, refusing a path outside the opened directory.
func (r RootCredFiles) name(path string) (string, error) {
	if filepath.Dir(path) != r.dir.Path() {
		return "", fmt.Errorf("%s is not in %s", path, r.dir.Path())
	}
	return filepath.Base(path), nil
}

func (r RootCredFiles) Lock(path string) (func(), error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	// A lock file root makes, or finds root's, goes to agents/' owner (the
	// engine's user), as config.LockFile does, so the engine can open it.
	unlock, err := config.LockAt(r.dir, name)
	if errors.Is(err, config.ErrLocked) {
		return nil, lockedError{path: path}
	}
	return unlock, err
}

func (r RootCredFiles) open(path string) (*os.File, error) {
	name, err := r.name(path)
	if err != nil {
		return nil, err
	}
	return r.dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func (r RootCredFiles) Read(path string) (string, os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	dsn, fi, err := readCredentialFrom(f, r.rules())
	if err != nil {
		return "", nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || r.self < 0 || uint64(st.Uid) != uint64(r.self) {
		if err := pgdial.CheckForeignDSN(dsn); err != nil {
			return "", nil, fmt.Errorf("it belongs to the owner of %s, not root: as root, basalt init --remote takes from it %w; "+
				"run basalt init --remote as that user (sudo -u <user>), or fix the file", r.dir.Path(), err)
		}
	}
	return dsn, fi, nil
}

func (r RootCredFiles) Stat(path string) (os.FileInfo, error) {
	f, err := r.open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func (r RootCredFiles) Write(path string, data []byte) error {
	name, err := r.name(path)
	if err != nil {
		return err
	}
	return r.dir.WriteFile(name, data, config.FileMode, r.owner)
}

func (r RootCredFiles) Rename(from, to string) error {
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

func (r RootCredFiles) Remove(path string) error {
	name, err := r.name(path)
	if err != nil {
		return err
	}
	return r.dir.Remove(name)
}

func (r RootCredFiles) Close() { _ = r.dir.Close() }
