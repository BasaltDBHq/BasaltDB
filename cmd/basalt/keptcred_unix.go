//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

const (
	// credentialPermMask is the permission bits a credential file must not have.
	credentialPermMask = 0o077
	rootUID            = 0
	// lockDirMode is the mode of a directory lockFile creates.
	lockDirMode = 0o700
)

// readKeptCredential reads the agent's existing credential file as root
// without following a symlink (the engine's user owns the directory and could
// plant one): see readCredentialFile. The file must be owned by the engine's
// user or root.
func readKeptCredential(path, engineUser string) (string, error) {
	line, _, err := readCredentialFile(path, func(uid uint32) (bool, string) {
		return uid == rootUID || ownedBy(uid, engineUser), engineUser + " or root"
	})
	return line, err
}

// readOwnCredential reads a credential file this process wrote (basalt init
// --remote: the credential file and its .pending), owned by this process's
// user, with readCredentialFile's checks. It returns the file read, so a
// caller can check the path still names it before moving it.
func readOwnCredential(path string) (string, os.FileInfo, error) {
	euid := os.Geteuid()
	return readCredentialFile(path, func(uid uint32) (bool, string) {
		return euid >= 0 && uint64(uid) == uint64(euid), "you"
	})
}

// readCredentialFile opens path with O_NOFOLLOW, then checks the open
// descriptor is a regular file with one link (a hard link could make the
// secret readable, or replaceable, by another path), mode 0600 or tighter,
// with an owner owner accepts, and reads from that descriptor, so nothing
// can change between check and read.
func readCredentialFile(path string, owner func(uid uint32) (ok bool, want string)) (string, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return "", nil, errors.New("not a regular file")
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", nil, fmt.Errorf("mode %o is more open than 0600", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", nil, errors.New("cannot read the file's owner")
	}
	if st.Nlink != 1 {
		return "", nil, fmt.Errorf("it has %d hard links; a credential file has one", st.Nlink)
	}
	if ok, want := owner(st.Uid); !ok {
		return "", nil, fmt.Errorf("owned by uid %d, not %s", st.Uid, want)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return "", nil, err
	}
	line := strings.TrimSpace(string(raw))
	if line == "" || len(raw) > maxCredentialBytes {
		return "", nil, errors.New("empty or too large")
	}
	return line, fi, nil
}

// lockFile takes an exclusive advisory lock on path (created 0600, never
// through a symlink) and returns its release. It does not wait: a lock held
// by another run is an error.
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), lockDirMode); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, config.FileMode)
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another basalt init --remote is running for this agent (%s is locked); run it again when it is done", path)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func ownedBy(uid uint32, name string) bool {
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return err == nil && uint32(id) == uid
}
