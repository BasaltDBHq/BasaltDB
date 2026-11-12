//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// credentialPermMask is the permission bits a credential file must not have.
const credentialPermMask = 0o077

// openEngineFile opens a file in the engine's own directories as root. The
// engine's user owns those directories and could plant a link, so every
// directory is reached from / without following one (service.OpenTrustedFile)
// and the open descriptor must be a regular file with one link owned by
// exactly the engine's user: not root, since a hardlink to an old root-only
// file keeps root as its owner. Checks and reads use the same descriptor.
func openEngineFile(path, engineUser string) (*os.File, error) {
	uid := service.LookupUID(engineUser)
	f, err := service.OpenTrustedFile(path, uid)
	if err != nil {
		return nil, err
	}
	if err := checkEngineFile(f, uid, engineUser); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func checkEngineFile(f *os.File, uid int, engineUser string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := config.CheckPlainFile(fi); err != nil {
		return fmt.Errorf("%s: %w", f.Name(), err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file's owner")
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not %s", f.Name(), st.Uid, engineUser)
	}
	return nil
}

// readKeptCredential reads the agent's existing credential file as root
// (openEngineFile), mode 0600 or tighter.
func readKeptCredential(path, engineUser string) (string, error) {
	f, err := openEngineFile(path, engineUser)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", fmt.Errorf("mode %o is more open than 0600", fi.Mode().Perm())
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
