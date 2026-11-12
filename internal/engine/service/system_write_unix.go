//go:build unix

package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	tempNameTries = 8
	tempNameBytes = 8
	// tempFileMode is the mode a temp file starts with, before the real mode
	// is set on its descriptor.
	tempFileMode = 0o600
	// ancestorDirMode is the mode of a missing parent directory.
	ancestorDirMode = 0o755
)

// afterDirOpen runs once the directory is held open; tests use it to swap the
// path for a symlink and prove writes still go to the held directory.
var afterDirOpen func()

// WriteFile writes data to path as root without following a link the engine
// user could plant. The directory holding the file is opened once with
// O_NOFOLLOW (its parent is root-controlled, so it is resolved normally) and
// everything after that is relative to that descriptor: a new temp file is
// created exclusively, its mode and owner are set through its own descriptor,
// and renameat moves it over the target. A symlink or hardlink at the target
// is replaced, never written through or re-owned.
func (OSSystem) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	ids, err := lookupOwner(owner)
	if err != nil {
		return err
	}
	dfd, err := openDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	if afterDirOpen != nil {
		afterDirOpen()
	}
	base := filepath.Base(path)
	f, tmp, err := createTempAt(dfd, base)
	if err != nil {
		return err
	}
	if err := fillTemp(f, data, mode, ids); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	if err := unix.Renameat(dfd, tmp, dfd, base); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	return nil
}

// Mkdir makes path (mode, owner) relative to its parent, refusing a symlink
// at path, and sets mode and owner through the opened directory descriptor.
func (OSSystem) Mkdir(path string, mode os.FileMode, owner string) error {
	ids, err := lookupOwner(owner)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && parent != path {
		// Missing ancestors are made by root (root-owned, 0755), like install -d.
		if err := (OSSystem{}).Mkdir(parent, ancestorDirMode, ""); err != nil {
			return err
		}
		pfd, err = unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	base := filepath.Base(path)
	if err := unix.Mkdirat(pfd, base, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	dfd, err := openDirAt(pfd, base, path)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	if err := unix.Fchmod(dfd, uint32(mode.Perm())); err != nil {
		return err
	}
	return unix.Fchown(dfd, ids.uid, ids.gid)
}

type ownerIDs struct{ uid, gid int }

// keepID tells chown to leave an id as it is.
const keepID = -1

// lookupOwner resolves the OS user; an empty name means "leave the owner".
func lookupOwner(name string) (ownerIDs, error) {
	if name == "" {
		return ownerIDs{uid: keepID, gid: keepID}, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return ownerIDs{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return ownerIDs{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return ownerIDs{}, err
	}
	return ownerIDs{uid: uid, gid: gid}, nil
}

// openDir opens dir with its last component not followed.
func openDir(dir string) (int, error) {
	parent := filepath.Dir(dir)
	if parent == dir {
		return unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	return openDirAt(pfd, filepath.Base(dir), dir)
}

func openDirAt(pfd int, name, full string) (int, error) {
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return -1, fmt.Errorf("%s is not a real directory (a symlink is refused)", full)
	}
	return fd, err
}

// createTempAt creates a new temp file next to base, relative to dfd.
func createTempAt(dfd int, base string) (*os.File, string, error) {
	for range tempNameTries {
		var rnd [tempNameBytes]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, "", err
		}
		name := "." + base + ".tmp-" + hex.EncodeToString(rnd[:])
		fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, tempFileMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", fmt.Errorf("cannot create a temp file for %s", base)
}

// fillTemp writes, sets mode and owner on the descriptor, and closes it.
func fillTemp(f *os.File, data []byte, mode os.FileMode, ids ownerIDs) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Chown(ids.uid, ids.gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
