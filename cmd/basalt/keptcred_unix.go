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

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

const (
	// credentialPermMask is the permission bits a credential file must not have.
	credentialPermMask = 0o077
	rootUID            = 0
)

// readKeptCredential reads the agent's existing credential file as root
// without following a symlink (the engine's user owns the directory and could
// plant one): it opens with O_NOFOLLOW, then checks the open descriptor is a
// regular file, mode 0600 or tighter, owned by the engine's user or root, and
// reads from that descriptor, so nothing can change between check and read.
func readKeptCredential(path, engineUser string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	// A regular file with one link: a hardlink to a root-only file the engine
	// user planted would otherwise be copied out as the credential.
	if err := config.CheckPlainFile(fi); err != nil {
		return "", err
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", fmt.Errorf("mode %o is more open than 0600", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot read the file's owner")
	}
	if st.Uid != rootUID && !ownedBy(st.Uid, engineUser) {
		return "", fmt.Errorf("owned by uid %d, not %s or root", st.Uid, engineUser)
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
