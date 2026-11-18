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
// user could plant. The directory holding the file is opened once by
// openTrusted (every component without following a link) and everything
// after that is relative to that descriptor: a new temp file is
// created exclusively, its mode and owner are set through its own descriptor,
// and renameat moves it over the target. A symlink or hardlink at the target
// is replaced, never written through or re-owned.
func (OSSystem) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	ids, err := lookupOwner(owner)
	if err != nil {
		return err
	}
	dfd, err := openTrusted(filepath.Dir(path), ids.uid)
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
// The parent is reached by openTrusted, so no component of it is a symlink
// the engine user planted. A directory that already exists is taken over
// only when root or owner owns it. group, when set, is the directory's
// group instead of owner's; a setgid mode keeps the bit.
func (OSSystem) Mkdir(path string, mode os.FileMode, owner, group string) error {
	ids, err := lookupOwner(owner)
	if err != nil {
		return err
	}
	if group != "" {
		if ids.gid, err = lookupGroup(group); err != nil {
			return err
		}
	}
	parent := filepath.Dir(path)
	pfd, err := openTrusted(parent, ids.uid)
	if errors.Is(err, unix.ENOENT) && parent != path {
		// Missing ancestors are made by root (root-owned, 0755), like install -d.
		if err := (OSSystem{}).Mkdir(parent, ancestorDirMode, "", ""); err != nil {
			return err
		}
		pfd, err = openTrusted(parent, ids.uid)
	}
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	base := filepath.Base(path)
	err = unix.Mkdirat(pfd, base, uint32(mode.Perm()))
	existed := errors.Is(err, unix.EEXIST)
	if err != nil && !existed {
		return err
	}
	dfd, err := openDirAt(pfd, base, path)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	if existed {
		if err := checkExisting(dfd, path, ids.uid, owner); err != nil {
			return err
		}
	}
	// Owner first: a chown clears the setgid bit, so the mode is set after.
	if err := unix.Fchown(dfd, ids.uid, ids.gid); err != nil {
		return err
	}
	return unix.Fchmod(dfd, modeBits(mode))
}

// lookupGroup is the gid of the OS group name.
func lookupGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// maxTreeDepth bounds how deep RemoveTree goes.
const maxTreeDepth = 32

// RemoveTree removes path and everything in it as root without following a
// link: its parent is reached by openTrusted (owned by root, writable by no
// one else on the way), and every entry below is removed relative to an
// open directory, a symlink as the link itself. A missing path is not an
// error.
func (OSSystem) RemoveTree(path string) error {
	pfd, err := openTrusted(filepath.Dir(path), 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	err = removeAt(pfd, filepath.Base(path), 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// removeAt removes name in the directory open at dfd: a file or link
// directly, a directory after what is in it.
func removeAt(dfd int, name string, depth int) error {
	err := unix.Unlinkat(dfd, name, 0)
	if err == nil || (!errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EPERM)) {
		return err
	}
	if depth >= maxTreeDepth {
		return fmt.Errorf("%s is nested too deep to remove", name)
	}
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(fd), name)
	names, err := d.Readdirnames(-1)
	if err != nil {
		_ = d.Close()
		return err
	}
	for _, n := range names {
		if err := removeAt(fd, n, depth+1); err != nil {
			_ = d.Close()
			return err
		}
	}
	if err := d.Close(); err != nil {
		return err
	}
	return unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR)
}

// checkExisting refuses to take over a directory that someone other than
// root or the intended owner made: chowning it would hand them a directory
// root then writes into.
func checkExisting(dfd int, path string, uid int, owner string) error {
	var st unix.Stat_t
	if err := fstat(dfd, &st); err != nil {
		return err
	}
	if dirPolicy.rootUID(st.Uid) || int(st.Uid) == uid {
		return nil
	}
	if owner == "" {
		owner = rootUser
	}
	return fmt.Errorf("%s already exists and is owned by uid %d, not root or %s; "+
		"move it aside (sudo mv %s %s.old) or choose another --config, then run the install again", path, st.Uid, owner, path, path)
}

type ownerIDs struct{ uid, gid int }

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

func openDirAt(pfd int, name, full string) (int, error) {
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return -1, notDirAt(pfd, name, full)
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
