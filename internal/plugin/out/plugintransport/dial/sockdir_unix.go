//go:build unix

package dial

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/lib/fileacl"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginpath"

	"golang.org/x/sys/unix"
)

// SocketDirIs reports whether dir, not followed if it is a link, is a
// directory owned by uid, in group gid, with no permission bit for others.
func SocketDirIs(dir string, uid, gid uint32) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && st.Gid == gid && fi.Mode().Perm()&0o007 == 0 && !openedByACL(dir)
}

// openedByACL reports whether path, not followed, has an ACL entry that
// allows any access: an ACL opens a file to other users without changing
// its mode, so a mode closed to others does not show it. An ACL that
// cannot be read counts as one.
func openedByACL(path string) bool {
	opens, err := fileacl.Opens(path, fileacl.Any)
	return err != nil || opens
}

// makeSocketDir makes the socket directory name in base, which has no
// symlink on the way. The base may be a directory other users can write
// (root's, with the sticky bit set, such as /tmp), so the directory is made
// and checked through descriptors, never by a path another user could
// change between two steps:
//
//   - base is opened without following a link, and the opened directory
//     passes the socket base rule again (plugin.CheckSocketBaseInfo);
//   - name is made in that descriptor with mode 0700, and anything already
//     there (a directory, a file, a symlink another user put there) fails
//     the call and is left as it is: there is no second try;
//   - the new directory is opened without following a link, set to 0700 on
//     that descriptor, and must then be a directory the engine's user owns,
//     of mode 0700, empty, and the one the path names (same device and
//     inode).
//
// Only the opened base is checked again: the directories above it passed
// plugin.CheckSocketBase, and as each is either writable by no one but root
// and the engine's user or root's and sticky, no other user can swap one.
// A umask that takes the owner's own bits away fails the open after mkdir.
// Any failure after the directory was made removes it. Another user cannot
// rename or remove it in a sticky directory, nor enter it, so its path stays
// the engine's for as long as it exists.
func makeSocketDir(base, name string) error {
	bf, err := os.OpenFile(base, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("the plugin socket base %s cannot be opened", base)
	}
	defer bf.Close()
	bfi, err := bf.Stat()
	if err != nil {
		return fmt.Errorf("the plugin socket base %s cannot be read", base)
	}
	if err := pluginpath.CheckSocketBaseInfo(base, bfi); err != nil {
		return err
	}
	bfd := int(bf.Fd())
	path := filepath.Join(base, name)
	if err := unix.Mkdirat(bfd, name, socketDirMode); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("the plugin socket directory %s already exists and was left as it is; nothing was started", path)
		}
		return errors.New("the plugin's socket directory could not be made")
	}
	if err := checkMadeSocketDir(bfd, name, path); err != nil {
		_ = unix.Unlinkat(bfd, name, unix.AT_REMOVEDIR)
		return err
	}
	return nil
}

// errSocketDirNotPrivate: the directory just made is not a private, empty
// directory of the engine's user at its path.
var errSocketDirNotPrivate = errors.New("the plugin's socket directory could not be made private")

// checkMadeSocketDir opens name in the base descriptor bfd without
// following a link, sets it to 0700 through that descriptor, and checks it:
// a directory the engine's user owns, mode 0700 exactly, empty, and the
// directory path names.
func checkMadeSocketDir(bfd int, name, path string) error {
	fd, err := unix.Openat(bfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errSocketDirNotPrivate
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	// mkdir applied the umask; the mode is set on the directory opened.
	if err := unix.Fchmod(fd, socketDirMode); err != nil {
		return errSocketDirNotPrivate
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return errSocketDirNotPrivate
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o7777 != socketDirMode {
		return errSocketDirNotPrivate
	}
	// An ACL entry the base passes on to new directories (macOS) opens it
	// as much as a mode would.
	if openedByACL(path) {
		return errSocketDirNotPrivate
	}
	if _, err := f.Readdirnames(1); !errors.Is(err, io.EOF) {
		return errSocketDirNotPrivate
	}
	var at unix.Stat_t
	if err := unix.Lstat(path, &at); err != nil || at.Dev != st.Dev || at.Ino != st.Ino {
		return errSocketDirNotPrivate
	}
	return nil
}
