//go:build unix

package engine

import (
	"fmt"
	"os"
	"syscall"
)

// ensurePrivateDirs makes each directory in dirs, 0700, and tightens one
// that is group or world accessible to 0700 when euid owns it. An update of
// a bot's computer drops empty folders and resets modes to 0755; the engine
// puts its own private folders right instead of refusing to start. A
// folder somebody else owns is left alone, and a symlink is refused: the
// engine never changes what it does not own or cannot see for what it is.
func ensurePrivateDirs(euid int, dirs ...string) error {
	for _, d := range dirs {
		if err := os.MkdirAll(d, stateDirMode); err != nil {
			return err
		}
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("%s is not a plain directory (a symlink or a file): the engine does not use it for its private files", d)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != euid {
			continue
		}
		if fi.Mode().Perm()&^stateDirMode != 0 {
			if err := os.Chmod(d, stateDirMode); err != nil {
				return fmt.Errorf("make %s private: %w", d, err)
			}
		}
	}
	return nil
}
