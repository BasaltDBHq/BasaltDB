//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

const (
	// credentialPermMask is the permission bits a credential file must not have.
	credentialPermMask = 0o077
)

// openEngineFile opens a file in the engine's own directories as root. The
// engine's user owns those directories and could plant a link, so every
// directory is reached from / without following one (service.OpenTrustedFile)
// and the open descriptor must be a regular file with one link owned by
// exactly the engine's user: not root, since a hardlink to an old root-only
// file keeps root as its owner. Checks and reads use the same descriptor.
// h reaches the file and the user's uid.
func openEngineFile(h setupFilesHost, path, engineUser string) (*os.File, error) {
	return openOwnedFile(h, path, h.OSLookupUID(engineUser), engineUser)
}

// openOwnedFile is openEngineFile for the user uid, named who in errors.
func openOwnedFile(h setupFilesHost, path string, uid int, who string) (*os.File, error) {
	f, err := h.OSOpenTrustedFile(path, uid)
	if err != nil {
		return nil, err
	}
	if err := checkEngineFile(f, uid, who); err != nil {
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
// readKeptCredential reads the engine user's credential for basalt service
// install when the role kept its password. Root only writes it back into
// the unit's files, owned by that user again, and never connects with it,
// so it takes no pgdial.CheckForeignDSN (TestRootCredentialReadsAreChecked).
func readKeptCredential(h setupFilesHost, path, engineUser string) (string, error) {
	return readOwnedCredential(h, path, h.OSLookupUID(engineUser), engineUser)
}

// readOwnedCredential is readKeptCredential for the user uid, named who in
// errors.
func readOwnedCredential(h setupFilesHost, path string, uid int, who string) (string, error) {
	f, err := openOwnedFile(h, path, uid, who)
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

// readOwnCredential reads a credential file this process wrote (basalt init
// --remote: the credential file and its .pending), owned by this process's
// user, with readCredentialFile's checks. It returns the file read, so a
// caller can check the path still names it before moving it.
func readOwnCredential(path string) (string, os.FileInfo, error) {
	return readCredentialFile(path, ownedByThisUser)
}

// ownedByThisUser accepts a file owned by this process's user.
func ownedByThisUser(uid uint32) (bool, string) {
	euid := os.Geteuid()
	return euid >= 0 && uint64(uid) == uint64(euid), "you"
}

// readCredentialFile opens path with O_NOFOLLOW and O_NONBLOCK (a FIFO
// planted at the path must not hang the read), then checks the open
// descriptor is a regular file with one link (a hard link could make the
// secret readable, or replaceable, by another path), mode 0600 or tighter,
// with an owner owner accepts, and reads from that descriptor, so nothing
// can change between check and read.
func readCredentialFile(path string, owner func(uid uint32) (ok bool, want string)) (string, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	return readCredentialFrom(f, owner)
}

// readCredentialFrom is readCredentialFile's checks and read on the open f.
func readCredentialFrom(f *os.File, owner func(uid uint32) (ok bool, want string)) (string, os.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	// A regular file with one link: a hardlink to a root-only file the engine
	// user planted would otherwise be copied out as the credential.
	if err := config.CheckPlainFile(fi); err != nil {
		return "", nil, err
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

// lockFile takes the agent's lock (config.LockFile), the one the engine
// also takes before it promotes a credential or clears a setup. It does not
// wait: a lock held by another run is an error.
func lockFile(path string) (func(), error) {
	unlock, err := config.LockFile(path)
	if errors.Is(err, config.ErrLocked) {
		return nil, fmt.Errorf("another basalt init --remote is running for this agent, or the engine is finishing its setup (%s is locked); run it again in a moment", path)
	}
	return unlock, err
}
