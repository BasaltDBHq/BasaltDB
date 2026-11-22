package pluginhost

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Mode is how the engine runs. Its values are engine.json's mode values.
type Mode string

// Modes.
const (
	// ModeService: installed files and the trust store belong to root.
	ModeService Mode = "SERVICE"
	// ModeSameUser: they belong to the engine's own user, which is no
	// security boundary (CONTRACT.md, Plugins, Isolation and trust). An empty
	// mode is same-user, as in engine.json.
	ModeSameUser Mode = "SAME_USER"
)

// rootUID is the uid of root.
const rootUID = 0

// maxSymlinkHops bounds how many root-owned symlinks above a root are
// followed, as the kernel bounds a path lookup.
const maxSymlinkHops = 40

// groupOtherWrite is the group and other write bits.
const groupOtherWrite = 0o022

// WhyGroupWritable is the path rule's refusal of a directory or file that
// its group or others can write.
const WhyGroupWritable = "can be written by group or others"

// errUnknownMode is a mode other than SERVICE and SAME_USER.
var errUnknownMode = errors.New("plugin: unknown engine mode")

// owner is the uid the path rule requires: root in service mode, the
// engine's own user in same-user mode.
func (m Mode) owner() (uint32, error) {
	switch m {
	case ModeService:
		return rootUID, nil
	case ModeSameUser, "":
		return currentUID()
	default:
		return 0, errUnknownMode
	}
}

// The root-owned base directory of plugins in service mode, per OS. It
// holds the installed copies and the trust store side by side, and every
// directory above it belongs to root. The config directory is not used in
// service mode: it may belong to the engine's OS user, which must not be
// able to change what is installed or trusted.
const (
	linuxServiceBase  = "/opt/basalt"
	darwinServiceBase = "/Library/Basalt"
	goosDarwin        = "darwin"
)

// The directory names under the base (service mode) or the config directory
// (same-user mode).
const (
	PluginsDirName = "plugins"
	TrustDirName   = "plugin-trust"
)

// base is the directory the plugin root and the trust store sit in: the
// service base per OS in service mode, the config directory (the directory
// that holds engine.json) in same-user mode. Another mode is refused.
func base(mode Mode, goos, configDir string) (string, error) {
	switch mode {
	case ModeService:
		if goos == goosDarwin {
			return darwinServiceBase, nil
		}
		return linuxServiceBase, nil
	case ModeSameUser, "":
		return configDir, nil
	default:
		return "", errUnknownMode
	}
}

// Root is the directory installed copies live under:
// /opt/basalt/plugins on Linux and /Library/Basalt/plugins on
// macOS in service mode, <configDir>/plugins in same-user mode.
func Root(mode Mode, goos, configDir string) (string, error) {
	b, err := base(mode, goos, configDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(b, PluginsDirName), nil
}

// TrustDir is the trust store's directory, next to Root:
// /opt/basalt/plugin-trust on Linux and
// /Library/Basalt/plugin-trust on macOS in service mode,
// <configDir>/plugin-trust in same-user mode.
func TrustDir(mode Mode, goos, configDir string) (string, error) {
	b, err := base(mode, goos, configDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(b, TrustDirName), nil
}

// pathRefusal is a path-rule failure. It names the path and the rule.
func pathRefusal(path, why string) *VerifyError {
	return &VerifyError{Reason: RefusedNotTrusted, File: path, Why: why}
}

// ruleRefusal is a refusal for who can write path, a symlink or its owner,
// with what was found there (VerifyError.Path).
func ruleRefusal(path, why string, kind PathFaultKind, fi fs.FileInfo, owners ...uint32) *VerifyError {
	r := pathRefusal(path, why)
	uid, _ := fileOwner(fi)
	r.Path = &PathFault{Kind: kind, UID: uid, GID: fileGroup(fi), Mode: fi.Mode(), Owners: owners}
	return r
}

// abovePolicy is how checkAbove judges the directories above a root.
type abovePolicy struct {
	// stickyRoot lets a directory that group or others can write pass when
	// root owns it and its sticky bit is set, as /tmp. Only the base of
	// same-user plugin socket directories takes it.
	stickyRoot bool
}

// checkAbove applies the path rule to every directory above base, "/"
// included (CONTRACT.md, Plugins, the path rule): each is owned by root or
// by owner and writable by no one else. A symlink there is followed only
// when root owns it; its target's components are checked the same way.
// ".." in a link target steps back over the components already resolved,
// as the kernel does. base itself and what is below it are checked by
// checkStrict.
func checkAbove(base string, owner uint32) error {
	return checkAboveWith(base, owner, abovePolicy{})
}

func checkAboveWith(base string, owner uint32, pol abovePolicy) error {
	if !filepath.IsAbs(base) {
		return pathRefusal(base, "is not an absolute path")
	}
	base = filepath.Clean(base)
	if err := checkAboveDir("/", owner, pol); err != nil {
		return err
	}
	pending := splitComponents(filepath.Dir(base))
	resolved := "/"
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		p := filepath.Join(resolved, c)
		fi, err := os.Lstat(p)
		if err != nil {
			return pathRefusal(p, "cannot be read")
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if err := checkAboveInfo(p, fi, owner, pol); err != nil {
				return err
			}
			resolved = p
			continue
		}
		uid, err := fileOwner(fi)
		if err != nil {
			return pathRefusal(p, "has an owner that cannot be read")
		}
		if uid != rootUID {
			return ruleRefusal(p, "is a symlink not owned by root", PathSymlink, fi, rootUID)
		}
		if hops++; hops > maxSymlinkHops {
			return pathRefusal(p, "has too many symlinks")
		}
		link, err := os.Readlink(p)
		if err != nil {
			return pathRefusal(p, "is a symlink that cannot be read")
		}
		if filepath.IsAbs(link) {
			resolved = "/"
		}
		pending = append(splitComponents(link), pending...)
	}
	return nil
}

// WhyNotStickyRoot refuses a socket base, or a directory above it, that
// group or others can write and that is not root's with the sticky bit set.
const WhyNotStickyRoot = WhyGroupWritable + ", and is not a directory root owns with the sticky bit set"

// CheckSocketBase applies the path rule's "above a root" check to dir and
// every directory above it, for the base same-user plugin socket
// directories are made in: each is owned by root or the engine's own user
// and writable by no one else, except that a directory root owns with the
// sticky bit set (such as /tmp) may be writable by group or others, since
// there no other user can rename or remove a directory the engine made. A
// symlink on the way is followed only when root owns it. The error is a
// *VerifyError naming the path and the rule.
func CheckSocketBase(dir string) error {
	owner, err := currentUID()
	if err != nil {
		return pathRefusal(dir, "has an owner that cannot be read")
	}
	// checkAbove checks the directories above its argument: name one inside
	// dir so dir itself is checked too.
	return checkAboveWith(filepath.Join(dir, "."+PluginsDirName), owner, abovePolicy{stickyRoot: true})
}

// CheckSocketBaseInfo is CheckSocketBase's rule for dir alone, judged from
// fi: the base's status read from a descriptor opened on it.
func CheckSocketBaseInfo(dir string, fi fs.FileInfo) error {
	owner, err := currentUID()
	if err != nil {
		return pathRefusal(dir, "has an owner that cannot be read")
	}
	return checkAboveInfo(dir, fi, owner, abovePolicy{stickyRoot: true})
}

func splitComponents(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}

func checkAboveDir(p string, owner uint32, pol abovePolicy) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return pathRefusal(p, "cannot be read")
	}
	return checkAboveInfo(p, fi, owner, pol)
}

// checkAboveInfo: a directory above a root is owned by root or owner and
// writable by no one else. A directory group or others can write fails,
// a sticky /tmp included, unless pol.stickyRoot is set and it is root's
// with the sticky bit.
func checkAboveInfo(p string, fi fs.FileInfo, owner uint32, pol abovePolicy) error {
	if !fi.IsDir() {
		return pathRefusal(p, "is not a directory")
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pathRefusal(p, "has an owner that cannot be read")
	}
	if uid != rootUID && uid != owner {
		return ruleRefusal(p, "is owned by a user other than root and the required owner", PathOwner, fi, rootUID, owner)
	}
	if fi.Mode().Perm()&groupOtherWrite == 0 {
		return nil
	}
	if !pol.stickyRoot {
		return ruleRefusal(p, WhyGroupWritable, PathWritable, fi, rootUID, owner)
	}
	if uid == rootUID && fi.Mode()&fs.ModeSticky != 0 {
		return nil
	}
	return ruleRefusal(p, WhyNotStickyRoot, PathWritable, fi, rootUID, owner)
}

// checkStrict applies the path rule to p at or below a root: it is not a
// symlink, it is owned by owner, and no one else can write it.
func checkStrict(p string, owner uint32) (fs.FileInfo, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, pathRefusal(p, "cannot be read")
	}
	return fi, checkStrictInfo(p, fi, owner)
}

func checkStrictInfo(p string, fi fs.FileInfo, owner uint32) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return ruleRefusal(p, "is a symlink", PathSymlink, fi)
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pathRefusal(p, "has an owner that cannot be read")
	}
	if uid != owner {
		return ruleRefusal(p, "is not owned by the required owner", PathOwner, fi, owner)
	}
	if fi.Mode().Perm()&groupOtherWrite != 0 {
		return ruleRefusal(p, WhyGroupWritable, PathWritable, fi, owner)
	}
	return nil
}

// checkUnder applies the path rule from "/" to each of dirs, where dirs[0]
// is the root and each later one lies inside the one before: above the root
// owned by root or owner, from the root down owned by owner.
func checkUnder(owner uint32, dirs ...string) error {
	if err := checkAbove(dirs[0], owner); err != nil {
		return err
	}
	for _, d := range dirs {
		fi, err := checkStrict(d, owner)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return pathRefusal(d, "is not a directory")
		}
	}
	return nil
}
