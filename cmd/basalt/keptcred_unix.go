//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

const (
	// credentialPermMask is the permission bits a credential file must not have.
	credentialPermMask = 0o077
	rootUID            = 0
)

// readKeptCredential reads the agent's existing credential file as root
// without following a symlink (the engine's user owns the directory and could
// plant one): see readCredentialFile. The file must be owned by the engine's
// user or root.
func readKeptCredential(path, engineUser string) (string, error) {
	return readCredentialFile(path, func(uid uint32) (bool, string) {
		return uid == rootUID || ownedBy(uid, engineUser), engineUser + " or root"
	})
}

// readOwnCredential reads a credential file this process wrote (basalt init
// --remote: the credential file and its .pending), owned by this process's
// user, with readCredentialFile's checks.
func readOwnCredential(path string) (string, error) {
	euid := os.Geteuid()
	return readCredentialFile(path, func(uid uint32) (bool, string) {
		return euid >= 0 && uint64(uid) == uint64(euid), "you"
	})
}

// readCredentialFile opens path with O_NOFOLLOW, then checks the open
// descriptor is a regular file, mode 0600 or tighter, with an owner owner
// accepts, and reads from that descriptor, so nothing can change between
// check and read.
func readCredentialFile(path string, owner func(uid uint32) (ok bool, want string)) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", fmt.Errorf("mode %o is more open than 0600", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot read the file's owner")
	}
	if ok, want := owner(st.Uid); !ok {
		return "", fmt.Errorf("owned by uid %d, not %s", st.Uid, want)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(raw))
	if line == "" || len(raw) > maxCredentialBytes {
		return "", errors.New("empty or too large")
	}
	return line, nil
}

func ownedBy(uid uint32, name string) bool {
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return err == nil && uint32(id) == uid
}
