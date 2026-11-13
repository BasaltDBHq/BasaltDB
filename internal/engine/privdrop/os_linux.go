package privdrop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// taskDir lists the process's threads.
const taskDir = "/proc/self/task"

// errCgoBuild is AllThreadsSyscall's answer in a cgo build.
var errCgoBuild = errors.New("this basalt was built with cgo, which cannot set it on every thread; use a release build (CGO_ENABLED=0)")

// NoNewPrivs sets no_new_privs on every thread of the process, so no exec
// it makes (setuid binaries, file capabilities) can gain privileges. It is
// a per-thread flag that new threads inherit, so it is set on all of them at
// once.
func (OS) NoNewPrivs() error {
	_, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	if errno == syscall.ENOTSUP {
		return errCgoBuild
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// Verify checks, for every thread in /proc/self/task, that all its user and
// group ids are a's, its groups are a's, it has no capability and
// no_new_privs is set, then that setuid(0) and setgid(0) fail.
func (OS) Verify(a Account) error {
	if err := verifyThreads(taskDir, a); err != nil {
		return err
	}
	return cannotRegain()
}

// verifyThreads checks every thread listed under dir.
func verifyThreads(dir string, a Account) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	checked := 0
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "status"))
		if errors.Is(err, fs.ErrNotExist) {
			continue // the thread exited
		}
		if err != nil {
			return err
		}
		st, err := parseStatus(string(raw))
		if err == nil {
			err = st.check(a)
		}
		if err != nil {
			return fmt.Errorf("thread %s: %w", e.Name(), err)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no thread found in %s", dir)
	}
	return nil
}
