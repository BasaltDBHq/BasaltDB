package pluginpath

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/fileacl"
)

// maxSymlinkHops bounds how many root-owned symlinks above a root are
// followed, as the kernel bounds a path lookup.
const maxSymlinkHops = 40

// groupOtherWrite is the group and other write bits.
const groupOtherWrite = 0o022

// Owner is the uid the path rule requires: root in service mode, the
// engine's own user in same-user mode.
func Owner(m pluginmodel.Mode) (uint32, error) {
	switch m {
	case pluginmodel.ModeService:
		return pluginmodel.RootUID, nil
	case pluginmodel.ModeSameUser, "":
		return CurrentUID()
	default:
		return 0, pluginmodel.ErrUnknownMode
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

// base is the directory the plugin root and the trust store sit in: the
// service base per OS in service mode, the config directory (the directory
// that holds engine.json) in same-user mode. Another mode is refused.
func base(mode pluginmodel.Mode, goos, configDir string) (string, error) {
	switch mode {
	case pluginmodel.ModeService:
		if goos == goosDarwin {
			return darwinServiceBase, nil
		}
		return linuxServiceBase, nil
	case pluginmodel.ModeSameUser, "":
		return configDir, nil
	default:
		return "", pluginmodel.ErrUnknownMode
	}
}

// Root is the directory installed copies live under:
// /opt/basalt/plugins on Linux and /Library/Basalt/plugins on
// macOS in service mode, <configDir>/plugins in same-user mode.
func Root(mode pluginmodel.Mode, goos, configDir string) (string, error) {
	b, err := base(mode, goos, configDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(b, pluginmodel.PluginsDirName), nil
}

// RuleRefusal is a refusal for who can write path, a symlink or its owner,
// with what was found there (pluginmodel.VerifyError.Path).
func RuleRefusal(path, why string, kind pluginmodel.PathFaultKind, fi fs.FileInfo, owners ...uint32) *pluginmodel.VerifyError {
	r := pluginmodel.PathRefusal(path, why)
	uid, _ := fileOwner(fi)
	r.Path = &pluginmodel.PathFault{Kind: kind, UID: uid, GID: fileGroup(fi), Mode: uint32(fi.Mode()), Owners: owners}
	return r
}

// abovePolicy is how CheckAbove judges the directories above a root.
type abovePolicy struct {
	// stickyRoot lets a directory that group or others can write pass when
	// root owns it and its sticky bit is set, as /tmp. Only the base of
	// same-user plugin socket directories takes it.
	stickyRoot bool
}

// CheckAbove applies the path rule to every directory above base, "/"
// included (CONTRACT.md, Plugins, the path rule): each is owned by root or
// by owner and writable by no one else. A symlink there is followed only
// when root owns it; its target's components are checked the same way.
// ".." in a link target steps back over the components already resolved,
// as the kernel does. base itself and what is below it are checked by
// CheckStrict.
func CheckAbove(base string, owner uint32) error {
	return checkAboveWith(base, owner, abovePolicy{})
}

func checkAboveWith(base string, owner uint32, pol abovePolicy) error {
	if !filepath.IsAbs(base) {
		return pluginmodel.PathRefusal(base, "is not an absolute path")
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
			return pluginmodel.PathRefusal(p, "cannot be read")
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
			return pluginmodel.PathRefusal(p, "has an owner that cannot be read")
		}
		if uid != pluginmodel.RootUID {
			return RuleRefusal(p, "is a symlink not owned by root", pluginmodel.PathSymlink, fi, pluginmodel.RootUID)
		}
		if hops++; hops > maxSymlinkHops {
			return pluginmodel.PathRefusal(p, "has too many symlinks")
		}
		link, err := os.Readlink(p)
		if err != nil {
			return pluginmodel.PathRefusal(p, "is a symlink that cannot be read")
		}
		if filepath.IsAbs(link) {
			resolved = "/"
		}
		pending = append(splitComponents(link), pending...)
	}
	return nil
}

// CheckSocketBase applies the path rule's "above a root" check to dir and
// every directory above it, for the base same-user plugin socket
// directories are made in: each is owned by root or the engine's own user
// and writable by no one else, except that a directory root owns with the
// sticky bit set (such as /tmp) may be writable by group or others, since
// there no other user can rename or remove a directory the engine made. A
// symlink on the way is followed only when root owns it. The error is a
// *pluginmodel.VerifyError naming the path and the rule.
func CheckSocketBase(dir string) error {
	owner, err := CurrentUID()
	if err != nil {
		return pluginmodel.PathRefusal(dir, "has an owner that cannot be read")
	}
	// CheckAbove checks the directories above its argument: name one inside
	// dir so dir itself is checked too.
	return checkAboveWith(filepath.Join(dir, "."+pluginmodel.PluginsDirName), owner, abovePolicy{stickyRoot: true})
}

// CheckSocketBaseInfo is CheckSocketBase's rule for dir alone, judged from
// fi: the base's status read from a descriptor opened on it.
func CheckSocketBaseInfo(dir string, fi fs.FileInfo) error {
	owner, err := CurrentUID()
	if err != nil {
		return pluginmodel.PathRefusal(dir, "has an owner that cannot be read")
	}
	return checkAboveInfo(dir, fi, owner, abovePolicy{stickyRoot: true})
}

func splitComponents(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}

func checkAboveDir(p string, owner uint32, pol abovePolicy) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return pluginmodel.PathRefusal(p, "cannot be read")
	}
	return checkAboveInfo(p, fi, owner, pol)
}

// checkAboveInfo: a directory above a root is owned by root or owner and
// writable by no one else, by its mode or an ACL entry (checkACL). A
// directory group or others can write fails, a sticky /tmp included, unless
// pol.stickyRoot is set and it is root's with the sticky bit.
func checkAboveInfo(p string, fi fs.FileInfo, owner uint32, pol abovePolicy) error {
	if !fi.IsDir() {
		return pluginmodel.PathRefusal(p, "is not a directory")
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pluginmodel.PathRefusal(p, "has an owner that cannot be read")
	}
	if uid != pluginmodel.RootUID && uid != owner {
		return RuleRefusal(p, "is owned by a user other than root and the required owner", pluginmodel.PathOwner, fi, pluginmodel.RootUID, owner)
	}
	if pol.stickyRoot && uid == pluginmodel.RootUID && fi.Mode()&fs.ModeSticky != 0 {
		// The sticky bit keeps others from replacing what they do not own,
		// whether the mode or an ACL lets them write the directory.
		return nil
	}
	if fi.Mode().Perm()&groupOtherWrite == 0 {
		return checkACL(p, fi, pluginmodel.RootUID, owner)
	}
	if !pol.stickyRoot {
		return RuleRefusal(p, pluginmodel.WhyGroupWritable, pluginmodel.PathWritable, fi, pluginmodel.RootUID, owner)
	}
	return RuleRefusal(p, pluginmodel.WhyNotStickyRoot, pluginmodel.PathWritable, fi, pluginmodel.RootUID, owner)
}

// CheckStrict applies the path rule to p at or below a root: it is not a
// symlink, it is owned by owner, and no one else can write it.
func CheckStrict(p string, owner uint32) (fs.FileInfo, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, pluginmodel.PathRefusal(p, "cannot be read")
	}
	return fi, CheckStrictInfo(p, fi, owner)
}

func CheckStrictInfo(p string, fi fs.FileInfo, owner uint32) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return RuleRefusal(p, "is a symlink", pluginmodel.PathSymlink, fi)
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pluginmodel.PathRefusal(p, "has an owner that cannot be read")
	}
	if uid != owner {
		return RuleRefusal(p, "is not owned by the required owner", pluginmodel.PathOwner, fi, owner)
	}
	if fi.Mode().Perm()&groupOtherWrite != 0 {
		return RuleRefusal(p, pluginmodel.WhyGroupWritable, pluginmodel.PathWritable, fi, owner)
	}
	return checkACL(p, fi, owner)
}

// checkACL refuses p, whose mode lets no one but its owner write it, when
// an allow entry in its ACL lets someone write it: an ACL opens a file to
// other users without changing its mode. The entry's user is not resolved
// (fileacl), so an entry for the owner counts too; deny entries, as macOS
// puts on a home directory, never do.
func checkACL(p string, fi fs.FileInfo, owners ...uint32) error {
	opens, err := fileacl.Opens(p, fileacl.Write)
	if err != nil {
		return pluginmodel.PathRefusal(p, "has an ACL that cannot be read")
	}
	if opens {
		return RuleRefusal(p, pluginmodel.WhyACLWritable, pluginmodel.PathWritable, fi, owners...)
	}
	return nil
}

// CheckUnder applies the path rule from "/" to each of dirs, where dirs[0]
// is the root and each later one lies inside the one before: above the root
// owned by root or owner, from the root down owned by owner.
func CheckUnder(owner uint32, dirs ...string) error {
	if err := CheckAbove(dirs[0], owner); err != nil {
		return err
	}
	for _, d := range dirs {
		fi, err := CheckStrict(d, owner)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return pluginmodel.PathRefusal(d, "is not a directory")
		}
	}
	return nil
}
