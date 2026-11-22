package pluginhost

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Sweep removes from the entry's own directory, <root>/<name>/<instance>/,
// what no entry uses: the temporary and set-aside copies a crashed add left
// (.staging-*, .old-*) and every installed copy but keep, the entry's
// manifestSha256. With keep "" the entry is gone: the directory is removed
// whole, and <root>/<name>/ too when no other instance is left in it.
// Nothing outside the entry's directory is touched, and nothing at all
// unless the path rule holds from "/" down to it. A missing directory is
// not an error.
func Sweep(root string, key EntryKey, keep string, mode Mode) error {
	owner, err := mode.owner()
	if err != nil {
		return err
	}
	if err := checkKey(key); err != nil {
		return err
	}
	nameDir := filepath.Join(root, key.Name)
	instDir := filepath.Join(nameDir, key.Instance)
	if _, err := os.Lstat(instDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := checkUnder(owner, root, nameDir, instDir); err != nil {
		return err
	}
	if keep == "" {
		if err := os.RemoveAll(instDir); err != nil {
			return pathRefusal(instDir, "cannot be removed")
		}
		// Only when empty: another instance of the plugin keeps it.
		_ = os.Remove(nameDir)
		return nil
	}
	des, err := os.ReadDir(instDir)
	if err != nil {
		return pathRefusal(instDir, "cannot be read")
	}
	for _, de := range des {
		if de.Name() == keep {
			continue
		}
		p := filepath.Join(instDir, de.Name())
		if err := os.RemoveAll(p); err != nil {
			return pathRefusal(p, "cannot be removed")
		}
	}
	return nil
}
