//go:build unix

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrLocked is a lock another process (or another holder in this one)
// holds.
var ErrLocked = errors.New("locked")

// LockUnusableError is a lock file this process cannot open or use: wrong
// permissions or owner (one a root process left behind), or not a regular
// file with one link. Retrying does not help; the engine reports it
// (CONTRACT.md, On the engine, Lock files).
type LockUnusableError struct {
	Path string
	Err  error
}

func (e *LockUnusableError) Error() string {
	return fmt.Sprintf("lock %s: %v", e.Path, e.Err)
}

func (e *LockUnusableError) Unwrap() error { return e.Err }

// rootUID is the superuser's uid.
const rootUID = 0

// dirOwner hands a lock file root creates to the owner of its directory.
const dirOwner = -1

// LockFile takes an exclusive advisory lock on path (created FileMode,
// never through a symlink, never blocking on a FIFO, and only on a regular
// file with one link) and returns its release. It does not wait: a lock
// held elsewhere is ErrLocked. basalt init --remote and the engine take the
// same lock, <credentialFile>.lock, before they change an agent's
// credential or its pending setup. A process running as root hands a lock
// file it creates, or finds owned by root, to the owner of its directory
// when that owner is not root, so the engine's user can always open it. A
// lock file that cannot be opened or used is a *LockUnusableError.
func LockFile(path string) (func(), error) {
	f, _, err := lockOpen(path, dirOwner)
	if err != nil {
		return nil, err
	}
	return HeldLock{f: f}.Release, nil
}

// HeldLock is a lock this process holds, on its open file.
type HeldLock struct {
	f *os.File
	// dirUID owned the lock's directory when it was opened.
	dirUID int
}

// Release unlocks and closes it.
func (h HeldLock) Release() {
	_ = syscall.Flock(int(h.f.Fd()), syscall.LOCK_UN)
	_ = h.f.Close()
}

// HandTo gives the lock file to uid when this process is root and the file
// is still root's: basalt service install calls it once the install made
// the engine's user, which may not exist when the lock is taken. dirUID is
// the owner of the directory the lock was opened in.
func (h HeldLock) HandTo(uid int) error {
	fi, err := h.f.Stat()
	if err != nil {
		return err
	}
	return handToOwner(h.f, fi, h.dirUID, uid)
}

// LockConfigAs is the config-wide lock (<config>.lock) for a root process
// that writes the config for the engine's user uid (basalt service
// install), waiting as every config writer does. A root-owned lock file is
// handed to uid (to its directory's owner while uid is unknown, < 0);
// HandTo hands it over again once the user exists.
func LockConfigAs(path string, uid int) (HeldLock, error) {
	var held HeldLock
	_, err := waitLock(func() (func(), error) {
		f, dirUID, err := lockOpen(path+".lock", uid)
		if err != nil {
			return nil, err
		}
		held = HeldLock{f: f, dirUID: dirUID}
		return held.Release, nil
	})
	return held, err
}

// lockOpen opens and locks path, handing a root-owned file to owner. The
// directory is opened once and the file opened in it (openat), so the
// directory whose owner decides the hand-over is the one the file is in,
// however the path's directories are swapped meanwhile.
func lockOpen(path string, owner int) (*os.File, int, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, 0, err
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("lock %s: %w", path, err)
	}
	defer unix.Close(dfd)
	var dst unix.Stat_t
	if err := unix.Fstat(dfd, &dst); err != nil {
		return nil, 0, fmt.Errorf("lock %s: %w", path, err)
	}
	fd, err := unix.Openat(dfd, filepath.Base(path), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, FileMode)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, 0, &LockUnusableError{Path: path, Err: err}
		}
		return nil, 0, fmt.Errorf("lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := lockOpened(f, int(dst.Uid), owner); err != nil {
		return nil, 0, err
	}
	return f, int(dst.Uid), nil
}

// LockOpenFile is LockFile on a lock file already opened (read-write, not
// following a link) in a directory owned by dirUID: a root caller opens it
// relative to a directory it reached without following one. A root-owned
// file is handed to dirUID as LockFile does. It takes f: on an error f is
// closed.
func LockOpenFile(f *os.File, dirUID int) (func(), error) {
	if err := lockOpened(f, dirUID, dirOwner); err != nil {
		return nil, err
	}
	return HeldLock{f: f, dirUID: dirUID}.Release, nil
}

// lockOpened checks the open lock file f (a regular file with one link),
// hands it over (handToOwner) and locks it; on an error f is closed.
func lockOpened(f *os.File, dirUID, owner int) error {
	path := f.Name()
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
	}
	if err != nil {
		_ = f.Close()
		return &LockUnusableError{Path: path, Err: err}
	}
	if err := handToOwner(f, fi, dirUID, owner); err != nil {
		_ = f.Close()
		return fmt.Errorf("lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return fmt.Errorf("lock %s: %w", path, ErrLocked)
	}
	return nil
}

// configLockWait is how long a config write waits for another to finish:
// each holds the lock for one read and one atomic write.
const configLockWait = 5 * time.Second

// configLockPoll is how often a waiting config write tries the lock again.
const configLockPoll = 20 * time.Millisecond

// lockConfig takes <path>.lock, the config-wide lock every read-modify-write
// of engine.json holds (UpsertAgentVault, ClearSetup), waiting up to
// configLockWait for another writer. Lock order: an agent's lock first,
// then this one.
func lockConfig(path string) (func(), error) {
	return waitLock(func() (func(), error) { return LockFile(path + ".lock") })
}

// waitLock retries lock while another holder has it, up to
// configLockWait.
func waitLock(lock func() (func(), error)) (func(), error) {
	deadline := time.Now().Add(configLockWait)
	for {
		unlock, err := lock()
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return unlock, err
		}
		time.Sleep(configLockPoll)
	}
}

// handToOwner gives the open lock file f to owner (dirOwner: the owner of
// its directory) when this process is root and f is root's, so the
// engine's user can open it later. Through the descriptor, never the path:
// the directory may be the engine user's.
func handToOwner(f *os.File, fi os.FileInfo, dirUID, owner int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, chown := lockHandOver(os.Geteuid(), int(st.Uid), dirUID, owner)
	if !chown {
		return nil
	}
	return f.Chown(uid, -1)
}

// lockHandOver decides who a lock file goes to: only a root process hands
// one over, only a file root owns, to owner, or to the directory's owner
// (dirUID) when owner is unknown (< 0), and never to root. A named owner
// gets it only in a directory that root or that owner owns: a lock file in
// a third user's directory is not root's to give away.
func lockHandOver(procUID, fileUID, dirUID, owner int) (int, bool) {
	if procUID != rootUID || fileUID != rootUID {
		return 0, false
	}
	switch {
	case owner < 0:
		owner = dirUID
	case dirUID != rootUID && dirUID != owner:
		return 0, false
	}
	return owner, owner > rootUID
}

// ReadOwnCredential reads a credential file this process's user owns: a
// regular file with one link, opened without following a symlink, mode
// 0600 or tighter. It returns the connection string and the file's info, so
// a later rename can check the path still names the file read.
func ReadOwnCredential(path string) (string, os.FileInfo, error) {
	return ReadOwnCredentialLimit(path, maxConfigBytes)
}

// ReadOwnCredentialLimit is ReadOwnCredential for a file of at most limit
// bytes, counted as stored (before the surrounding space is trimmed).
func ReadOwnCredentialLimit(path string, limit int) (string, os.FileInfo, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", nil, fmt.Errorf("%s is mode %o; a credential file is readable by its owner only (0600)", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil, errors.New("cannot read the file's owner")
	}
	if uint64(st.Uid) != uint64(os.Geteuid()) {
		return "", nil, fmt.Errorf("%s is owned by uid %d, not this process's user", path, st.Uid)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return "", nil, err
	}
	dsn := strings.TrimSpace(string(raw))
	if dsn == "" || len(raw) > limit {
		return "", nil, fmt.Errorf("%s is empty or too large", path)
	}
	return dsn, fi, nil
}

// SameCredentialFile reports whether path still names the file fi describes,
// a regular file with one link.
func SameCredentialFile(path string, fi os.FileInfo) error {
	now, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := CheckPlainFile(now); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !os.SameFile(now, fi) {
		return fmt.Errorf("%s changed since it was read", path)
	}
	return nil
}
