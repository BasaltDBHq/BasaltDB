package plugin

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

// Linux and macOS roots of installed copies in service mode.
const (
	linuxServiceRoot  = "/usr/local/lib/basalt/plugins"
	darwinServiceRoot = "/Library/Application Support/Basalt/plugins"
	goosDarwin        = "darwin"
)

// TrustDirName is the trust store's directory under the config directory.
const TrustDirName = "plugin-trust"

// Root is the directory installed copies live under: in service mode
// /usr/local/lib/basalt/plugins on Linux and /Library/Application
// Support/Basalt/plugins on macOS, in same-user mode <configDir>/plugins,
// where configDir is the directory that holds engine.json. Another mode is
// refused.
func Root(mode Mode, goos, configDir string) (string, error) {
	switch mode {
	case ModeService:
		if goos == goosDarwin {
			return darwinServiceRoot, nil
		}
		return linuxServiceRoot, nil
	case ModeSameUser, "":
		return filepath.Join(configDir, "plugins"), nil
	default:
		return "", errUnknownMode
	}
}

// TrustDir is <configDir>/plugin-trust.
func TrustDir(configDir string) string { return filepath.Join(configDir, TrustDirName) }

// pathRefusal is a path-rule failure. It names the path and the rule.
func pathRefusal(path, why string) *VerifyError {
	return &VerifyError{Reason: RefusedNotTrusted, File: path, Why: why}
}

// checkAbove applies the path rule to every directory above base, "/"
// included (CONTRACT.md, Plugins, the path rule): each is owned by root or
// by owner and writable by no one else. A symlink there is followed only
// when root owns it; its target's components are checked the same way.
// ".." in a link target steps back over the components already resolved,
// as the kernel does. base itself and what is below it are checked by
// checkStrict.
func checkAbove(base string, owner uint32) error {
	if !filepath.IsAbs(base) {
		return pathRefusal(base, "is not an absolute path")
	}
	base = filepath.Clean(base)
	if err := checkAboveDir("/", owner); err != nil {
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
			if err := checkAboveInfo(p, fi, owner); err != nil {
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
			return pathRefusal(p, "is a symlink not owned by root")
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

func splitComponents(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}

func checkAboveDir(p string, owner uint32) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return pathRefusal(p, "cannot be read")
	}
	return checkAboveInfo(p, fi, owner)
}

// checkAboveInfo: a directory above a root is owned by root or owner and
// writable by no one else. A world-writable sticky directory such as /tmp
// fails: another user could not replace its entries, but the rule does not
// make that exception.
func checkAboveInfo(p string, fi fs.FileInfo, owner uint32) error {
	if !fi.IsDir() {
		return pathRefusal(p, "is not a directory")
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pathRefusal(p, "has an owner that cannot be read")
	}
	if uid != rootUID && uid != owner {
		return pathRefusal(p, "is owned by a user other than root and the required owner")
	}
	if fi.Mode().Perm()&groupOtherWrite != 0 {
		return pathRefusal(p, "can be written by group or others")
	}
	return nil
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
		return pathRefusal(p, "is a symlink")
	}
	uid, err := fileOwner(fi)
	if err != nil {
		return pathRefusal(p, "has an owner that cannot be read")
	}
	if uid != owner {
		return pathRefusal(p, "is not owned by the required owner")
	}
	if fi.Mode().Perm()&groupOtherWrite != 0 {
		return pathRefusal(p, "can be written by group or others")
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
