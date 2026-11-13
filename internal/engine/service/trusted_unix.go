//go:build unix

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// groupOtherWrite are the mode bits that let someone besides the owner
	// change a directory's entries.
	groupOtherWrite = 0o022
	// permBits are a mode's permission bits with setuid, setgid and sticky.
	permBits = 0o7777
	// maxLinks bounds the root-owned symlinks openTrusted follows.
	maxLinks = 16
	// linkBufSize is the buffer for one symlink target.
	linkBufSize = 4096

	dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
)

// trustPolicy says which directory owners count as root. Tests widen it to
// the test user (and a sticky /tmp), since they do not run as root; the
// symlink rule in openTrusted always wants uid 0.
type trustPolicy struct {
	rootUIDs []uint32
	stickyOK bool
}

func (p trustPolicy) rootUID(uid uint32) bool { return slices.Contains(p.rootUIDs, uid) }

var dirPolicy = trustPolicy{rootUIDs: []uint32{0}}

// fstat is unix.Fstat; tests replace it to make a directory look owned by
// another user.
var fstat = unix.Fstat

// openTrusted opens dir for root without letting another user redirect it.
// It walks from / one component at a time with openat(O_NOFOLLOW), so a
// component swapped for a symlink is refused rather than followed, and each
// directory it passes must be owned by root (or by owner, the engine user,
// for the engine's own directories) and not writable by group or others:
// otherwise its owner or group could rename a component after the check.
// One exception keeps system paths working: a root-owned symlink reached
// through directories only root can change (macOS /etc -> private/etc) is
// followed, since only root can change it either.
func openTrusted(dir string, owner int) (int, error) {
	if !filepath.IsAbs(dir) {
		return -1, fmt.Errorf("%s is not an absolute path", dir)
	}
	path := filepath.Clean(dir)
	for range maxLinks {
		fd, next, err := walkTrusted(path, owner)
		if next == "" {
			return fd, err
		}
		path = next
	}
	return -1, fmt.Errorf("%s: too many symlinks", dir)
}

// walkTrusted opens path from /. When it meets a symlink it may follow, it
// returns next, the path to walk again from /.
func walkTrusted(path string, owner int) (fd int, next string, err error) {
	fd, err = unix.Open("/", dirFlags, 0)
	if err != nil {
		return -1, "", err
	}
	rootOnly, err := checkDir(fd, "/", owner)
	if err != nil {
		unix.Close(fd)
		return -1, "", err
	}
	cur := "/"
	comps := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range comps {
		if name == "" {
			continue
		}
		full := filepath.Join(cur, name)
		nfd, err := unix.Openat(fd, name, dirFlags|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			next, err := followLink(fd, name, full, rootOnly, comps[i+1:])
			unix.Close(fd)
			return -1, next, err
		}
		unix.Close(fd)
		if err != nil {
			return -1, "", fmt.Errorf("open %s: %w", full, err)
		}
		fd, cur = nfd, full
		ok, err := checkDir(fd, cur, owner)
		if err != nil {
			unix.Close(fd)
			return -1, "", err
		}
		rootOnly = rootOnly && ok
	}
	return fd, "", nil
}

// followLink resolves the symlink name in dfd (at full) to the path to walk
// again, with rest appended, when root alone controls it; anything else is
// refused.
func followLink(dfd int, name, full string, rootOnly bool, rest []string) (string, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if statMode(st.Mode)&unix.S_IFMT != unix.S_IFLNK {
		return "", notDir(full)
	}
	if !rootOnly || st.Uid != 0 {
		return "", symlinkRefused(full)
	}
	buf := make([]byte, linkBufSize)
	n, err := unix.Readlinkat(dfd, name, buf)
	if err != nil {
		return "", err
	}
	target := string(buf[:n])
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(full), target)
	}
	return filepath.Join(append([]string{target}, rest...)...), nil
}

func symlinkRefused(full string) error {
	return fmt.Errorf("%s is not a real directory (a symlink is refused)", full)
}

func notDir(full string) error {
	return fmt.Errorf("%s is not a directory", full)
}

// notDirAt says why name in dfd could not be opened as a directory: it is a
// symlink, or something else.
func notDirAt(dfd int, name, full string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && statMode(st.Mode)&unix.S_IFMT != unix.S_IFLNK {
		return notDir(full)
	}
	return symlinkRefused(full)
}

// OpenTrustedFile opens path read-only for root: its directory through
// openTrusted (owner is the uid that may own directories on the way, -1 for
// none), and the file with O_NOFOLLOW relative to it. The caller checks the
// open file (type, links, owner) through its descriptor.
func OpenTrustedFile(path string, owner int) (*os.File, error) {
	dfd, err := openTrusted(filepath.Dir(path), owner)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	base := filepath.Base(path)
	fd, err := unix.Openat(dfd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%s is a symlink, which is refused", path)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// checkDir refuses a directory root cannot trust to stay put: owned by
// anyone but root or owner, or writable by group or others. rootOnly is
// whether only root (uid 0) can change it.
func checkDir(fd int, path string, owner int) (rootOnly bool, err error) {
	var st unix.Stat_t
	if err := fstat(fd, &st); err != nil {
		return false, err
	}
	perm := statMode(st.Mode) & permBits
	writable := perm&groupOtherWrite != 0
	if writable && dirPolicy.stickyOK && perm&unix.S_ISVTX != 0 && dirPolicy.rootUID(st.Uid) {
		writable = false
	}
	switch {
	case writable:
		return false, fmt.Errorf("%s is writable by group or others (mode %04o), so another user could redirect what root writes below it; "+
			"remove that access (sudo chmod go-w %s) or choose a --config under directories only root can change", path, perm, path)
	case !dirPolicy.rootUID(st.Uid) && int(st.Uid) != owner:
		return false, fmt.Errorf("%s is owned by uid %d, not root, so that user could redirect what root writes below it; "+
			"choose a --config under directories only root can change (or sudo chown root %s)", path, st.Uid, path)
	}
	return st.Uid == 0 && perm&groupOtherWrite == 0, nil
}

// statMode is the mode of a unix.Stat_t as uint32. The field is uint16 on
// darwin and freebsd and uint32 on linux and the other unixes; a generic
// conversion is needed on the first and is not flagged as unnecessary on the
// second, so no per-OS file is needed.
func statMode[T ~uint16 | ~uint32](m T) uint32 { return uint32(m) }
