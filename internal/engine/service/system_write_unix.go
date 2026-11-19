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
	"time"

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

// CreateFile makes path an empty file with mode, owned by owner, when it is
// missing, and keeps an existing one's content: a log a service appends to.
// Its directory is reached by openTrusted with root as the only trusted
// owner, so only root can have put anything at path. A missing file is
// created exclusively without following a link; an existing one is opened
// without following a link and must be a regular file with no other name,
// unless it already belongs to owner (a hard link to anyone else's file is
// refused, never re-owned). Mode and owner are set through the descriptor.
func (OSSystem) CreateFile(path string, mode os.FileMode, owner string) error {
	ids, err := lookupOwner(owner)
	if err != nil {
		return err
	}
	dfd, err := openTrusted(filepath.Dir(path), keepID)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	base := filepath.Base(path)
	fd, err := unix.Openat(dfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, tempFileMode)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(dfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	}
	if errors.Is(err, unix.ELOOP) {
		return symlinkError(path)
	}
	if err != nil {
		return &os.PathError{Op: opOpen, Path: path, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := fstat(fd, &st); err != nil {
		return err
	}
	// A file with another name is taken over only when it is already the
	// owner's: the directory is root's, so only that owner (who could link
	// its own log elsewhere) made the other name, and fchown and fchmod then
	// change nothing of anyone else's.
	ownLink := ids.uid >= 0 && int(st.Uid) == ids.uid
	if statMode(st.Mode)&unix.S_IFMT != unix.S_IFREG || (st.Nlink != 1 && !ownLink) {
		return fmt.Errorf("%s is not a plain file (a hard link, a directory or a device?); refusing to take it over; "+
			"move it aside (sudo mv %s %s.old) and run the install again", path, path, path)
	}
	if err := clearUserFlags(fd); err != nil {
		return err
	}
	if err := unix.Fchown(fd, ids.uid, ids.gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

// movedNameTries bounds the names MoveAside tries when one is taken.
const movedNameTries = 100

// MoveAside renames the directory at path to "<path>.old-<UTC time>" when
// the OS user owner owns it, and returns the new name. Its parent is reached
// by openTrusted with root as the only trusted owner, so only root can
// change the entry at path meanwhile; the directory is checked through a
// descriptor opened without following a link and renamed as a whole,
// relative to the parent, so nothing inside it is followed, read or
// re-owned. A missing path, one owned by anyone else, or an owner with no
// account, is left as it is (""); a link or a file at path is refused.
func (OSSystem) MoveAside(path, owner string) (string, error) {
	uid := LookupUID(owner)
	if uid < 0 {
		return "", nil
	}
	pfd, err := openTrusted(filepath.Dir(path), keepID)
	if err != nil {
		return "", err
	}
	defer unix.Close(pfd)
	base := filepath.Base(path)
	dfd, err := openDirAt(pfd, base, path)
	if errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := fstat(dfd, &st); err != nil {
		return "", err
	}
	if int(st.Uid) != uid {
		return "", nil
	}
	// An owner who made the directory immutable would stop the rename.
	if err := clearUserFlags(dfd); err != nil {
		return "", err
	}
	stamp := base + ".old-" + time.Now().UTC().Format("20060102T150405Z")
	for i := range movedNameTries {
		name := stamp
		if i > 0 {
			name += "-" + strconv.Itoa(i)
		}
		var other unix.Stat_t
		err := unix.Fstatat(pfd, name, &other, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			continue
		}
		if !errors.Is(err, unix.ENOENT) {
			return "", err
		}
		if err := unix.Renameat(pfd, base, pfd, name); err != nil {
			return "", &os.LinkError{Op: "rename", Old: path, New: filepath.Join(filepath.Dir(path), name), Err: err}
		}
		return filepath.Join(filepath.Dir(path), name), nil
	}
	return "", fmt.Errorf("cannot find a free name to move %s aside", path)
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
