//go:build unix

package credfiles

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// OpenEngineFile opens a file in the engine's own directories as root. The
// engine's user owns those directories and could plant a link, so every
// directory is reached from / without following one (service.OpenTrustedFile)
// and the open descriptor must be a regular file with one link owned by
// exactly the engine's user: not root, since a hardlink to an old root-only
// file keeps root as its owner. Checks and reads use the same descriptor.
// h reaches the file and the user's uid.
func OpenEngineFile(h FilesHost, path, engineUser string) (*os.File, error) {
	return openOwnedFile(h, path, h.OSLookupUID(engineUser), engineUser)
}

// openOwnedFile is OpenEngineFile for the user uid, named who in errors.
func openOwnedFile(h FilesHost, path string, uid int, who string) (*os.File, error) {
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
	if err := ownerfile.CheckPlain(fi); err != nil {
		return fmt.Errorf("%s: %w", f.Name(), err)
	}
	if err := ownerfile.CheckOwner(fi, ownerfile.Rules{Owners: []int{uid}, OwnerName: engineUser}); err != nil {
		return fmt.Errorf("%s: %w", f.Name(), err)
	}
	return nil
}

// ReadKeptCredential reads the agent's existing credential file as root
// (OpenEngineFile), mode 0600 or tighter: the engine user's credential for
// basalt service install when the role kept its password. Root only writes
// it back into
// the unit's files, owned by that user again, and never connects with it,
// so it takes no pgdial.CheckForeignDSN (TestRootCredentialReadsAreChecked).
func ReadKeptCredential(h FilesHost, path, engineUser string) (string, error) {
	return readOwnedCredential(h, path, h.OSLookupUID(engineUser), engineUser)
}

// readOwnedCredential is ReadKeptCredential for the user uid, named who in
// errors: the file reached as OpenEngineFile reaches it, with
// readCredentialFrom's checks for an owner of exactly uid.
func readOwnedCredential(h FilesHost, path string, uid int, who string) (string, error) {
	f, err := h.OSOpenTrustedFile(path, uid)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, _, err := ownerfile.ReadOpen(f, ownerfile.Rules{Owners: []int{uid}, OwnerName: who, MaxBytes: MaxCredentialBytes})
	defer clear(raw)
	if re := ownerfile.Refusal(err); re != nil && re.Rule != ownerfile.TooLarge {
		return "", fmt.Errorf("%s: %w", f.Name(), re)
	}
	return credentialLine(raw, err)
}

// readOwnCredential reads a credential file this process wrote (basalt init
// --remote: the credential file and its .pending), owned by this process's
// effective user, with readCredentialFrom's checks. It returns the file
// read, so a caller can check the path still names the file before moving
// it.
func readOwnCredential(path string) (string, os.FileInfo, error) {
	return readCredentialFile(path, ownerfile.Rules{OwnerName: "you", MaxBytes: MaxCredentialBytes})
}

// readCredentialFile opens path without following a symlink and without
// blocking on a FIFO (ownerfile.OpenNoFollow), then reads it with
// readCredentialFrom's checks.
func readCredentialFile(path string, r ownerfile.Rules) (string, os.FileInfo, error) {
	f, err := ownerfile.OpenNoFollow(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	return readCredentialFrom(f, r)
}

// readCredentialFrom checks the open f with ownerfile's rules (a regular
// file with one link, so a hardlink to a root-only file the engine user
// planted is never copied out as the credential; mode 0600 or tighter; an
// owner r names; at most MaxCredentialBytes) and reads it from that
// descriptor, so nothing can change between check and read. It returns the
// trimmed line.
func readCredentialFrom(f *os.File, r ownerfile.Rules) (string, os.FileInfo, error) {
	raw, fi, err := ownerfile.ReadOpen(f, r)
	defer clear(raw)
	line, err := credentialLine(raw, err)
	if err != nil {
		return "", nil, err
	}
	return line, fi, nil
}

// credentialLine is a credential file's trimmed text, or err. A file over
// MaxCredentialBytes and an empty one are one error.
func credentialLine(raw []byte, err error) (string, error) {
	if re := ownerfile.Refusal(err); re != nil && re.Rule == ownerfile.TooLarge {
		return "", errors.New("empty or too large")
	}
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return "", errors.New("empty or too large")
	}
	return line, nil
}

// lockFile takes the agent's lock (config.LockFile), the one the engine
// also takes before it promotes a credential or clears a setup. It does not
// wait: a lock held by another run is an error.
func lockFile(path string) (func(), error) {
	unlock, err := config.LockFile(path)
	if errors.Is(err, config.ErrLocked) {
		return nil, lockedError{path: path}
	}
	return unlock, err
}

// lockedError is the agent's lock held by another run: init --remote's
// message, still config.ErrLocked for errors.Is.
type lockedError struct{ path string }

func (e lockedError) Error() string {
	return fmt.Sprintf("another basalt init --remote is running for this agent, or the engine is finishing its setup (%s is locked); run it again in a moment", e.path)
}

func (lockedError) Unwrap() error { return config.ErrLocked }
