package osservice

import (
	"fmt"
	"os"
	"path/filepath"
)

// The engine service's own copy of basalt (CONTRACT.md, The administrator
// dialog): the install and the restart copy the basalt that runs them here,
// root's, so the service never runs a binary in a folder the person's
// account can write (a Homebrew prefix, a download folder). macOS keeps
// /usr/libexec for the system, so its copy is under /usr/local; Linux's is
// under /usr, which some distributions keep apart from /usr/local's group.
const (
	darwinServiceBinary = "/usr/local/libexec/basalt"
	linuxServiceBinary  = "/usr/libexec/basalt"
)

// ServiceBinary is the path of the engine service's copy of basalt on goos:
// the binary its unit runs.
func ServiceBinary(goos string) string {
	if goos == goosDarwin {
		return darwinServiceBinary
	}
	return linuxServiceBinary
}

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

// unprotectedBinary is the check's error. The service's binary is the copy
// basalt init makes, root's, in the administrator dialog: a check that
// fails means that copy failed or was changed, and basalt init makes it
// again.
func unprotectedBinary(binary, path, problem string) error {
	return fmt.Errorf("%s %s: the engine service runs %s as the engine's OS user, so only root may be able to change it or any directory above it. "+
		"basalt init copies basalt there, root's, in the system's administrator dialog: run basalt init again",
		path, problem, binary)
}
