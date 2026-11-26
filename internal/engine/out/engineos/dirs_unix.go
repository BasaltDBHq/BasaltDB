//go:build unix

package engineos

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// MakePrivateDirs makes each directory in dirs with mode, and tightens one
// that has more than mode to mode when euid owns it. An update of
// a bot's computer drops empty folders and resets modes to 0755; the engine
// puts its own private folders right instead of refusing to start. A
// folder somebody else owns is left alone, and a symlink is refused: the
// engine never changes what it does not own or cannot see for what it is.
// The mode is changed through the open folder, so a symlink swapped in
// meanwhile is never followed.
func (OS) MakePrivateDirs(euid int, mode os.FileMode, dirs ...string) error {
	for _, d := range dirs {
		if err := ensurePrivateDir(euid, mode, d); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateDir(euid int, mode os.FileMode, d string) error {
	notPlain := fmt.Errorf("%s is not a plain directory (a symlink or a file): the engine does not use it for its private files", d)
	if fi, err := os.Lstat(d); err == nil {
		if !fi.IsDir() {
			return notPlain
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := os.MkdirAll(d, mode); err != nil {
		return err
	}
	f, err := os.OpenFile(d, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return notPlain
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != euid || fi.Mode().Perm()&^mode == 0 {
		return nil
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("make %s private: %w", d, err)
	}
	return nil
}
