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
)

// ErrLocked is a lock another process (or another holder in this one)
// holds.
var ErrLocked = errors.New("locked")

// LockFile takes an exclusive advisory lock on path (created FileMode,
// never through a symlink, never blocking on a FIFO, and only on a regular
// file with one link) and returns its release. It does not wait: a lock
// held elsewhere is ErrLocked. basalt init --remote and the engine take the
// same lock, <credentialFile>.lock, before they change an agent's
// credential or its pending setup.
func LockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, FileMode)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err == nil {
		err = CheckPlainFile(fi)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, ErrLocked)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
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
	deadline := time.Now().Add(configLockWait)
	for {
		unlock, err := LockFile(path + ".lock")
		if !errors.Is(err, ErrLocked) || time.Now().After(deadline) {
			return unlock, err
		}
		time.Sleep(configLockPoll)
	}
}

// ReadOwnCredential reads a credential file this process's user owns: a
// regular file with one link, opened without following a symlink, mode
// 0600 or tighter. It returns the connection string and the file's info, so
// a later rename can check the path still names the file read.
func ReadOwnCredential(path string) (string, os.FileInfo, error) {
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
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return "", nil, err
	}
	dsn := strings.TrimSpace(string(raw))
	if dsn == "" || len(raw) > maxConfigBytes {
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
