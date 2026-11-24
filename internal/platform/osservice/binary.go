package osservice

import (
	"fmt"
	"os"
	"path/filepath"
)

// protectedBinaryDir is where the fix message tells a person to install
// basalt when its current place is not protected.
const protectedBinaryDir = "/usr/local/libexec"

// binaryWriteBits are the mode bits that let someone besides the owner
// change a file or a directory's entries.
const binaryWriteBits = 0o022

// FileStat is what the binary check needs to know about one path, from
// lstat: its owner and its mode (type and permission bits).
type FileStat struct {
	UID  uint32
	Mode os.FileMode
}

// StatFunc lstats a path.
type StatFunc func(path string) (FileStat, error)

// CheckBinary refuses a binary the engine's OS user, or anyone but root,
// could replace: the service manager runs it as the engine user, so whoever
// can change it runs code with the engine's credential. Like sshd's
// StrictModes, the file and every directory above it must be owned by root
// and not writable by group or others (a root:admin or root:wheel group is
// fine when it cannot write). A symlink on the way is accepted when root
// owns it, since its directory is checked too; the caller checks the
// resolved path as well.
func CheckBinary(path string, lstat StatFunc) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("binary path %q must be absolute", path)
	}
	path = filepath.Clean(path)
	for p := path; ; p = filepath.Dir(p) {
		st, err := lstat(p)
		if err != nil {
			return fmt.Errorf("binary %s: %w", path, err)
		}
		if problem := binaryProblem(st, p == path); problem != "" {
			return unprotectedBinary(path, p, problem)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// binaryProblem says what is wrong with one path on the way, or "".
func binaryProblem(st FileStat, isBinary bool) string {
	switch {
	case st.UID != 0:
		return fmt.Sprintf("is owned by uid %d, not root", st.UID)
	case st.Mode&os.ModeSymlink != 0:
		return ""
	case st.Mode.Perm()&binaryWriteBits != 0:
		return fmt.Sprintf("is writable by group or others (mode %04o)", st.Mode.Perm())
	case isBinary && !st.Mode.IsRegular():
		return "is not a regular file"
	}
	return ""
}

func unprotectedBinary(binary, path, problem string) error {
	target := protectedBinaryDir + "/basalt"
	return fmt.Errorf("%s %s: the engine service runs %s as the engine's OS user, so only root may be able to change it or any directory above it. "+
		"Install basalt in a root-owned directory and run that copy: sudo install -d -o root -m 0755 %s && sudo install -o root -m 0755 %s %s, "+
		"then run %s with the same arguments (see docs/install.md, step 1)",
		path, problem, binary, protectedBinaryDir, binary, target, target)
}
