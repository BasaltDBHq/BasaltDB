package plugin

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Sweep removes from the entry's own directory, <root>/<name>/<instance>/,
// what no entry uses: the temporary and set-aside copies a crashed add left
// (.staging-*, .old-*) and every installed copy but keep, the entry's
// manifestSha256. With keep "" the entry is gone: the directory is removed
// whole, and <root>/<name>/ too when no other instance is left in it.
// Nothing outside the entry's directory is touched, and nothing at all
// unless the path rule holds from "/" down to it. A missing directory is
// not an error. It reads and removes through files.
func Sweep(files Files, root string, key pluginmodel.EntryKey, keep string, mode pluginmodel.Mode) error {
	owner, err := requiredOwner(mode)
	if err != nil {
		return err
	}
	if err := checkKey(key); err != nil {
		return err
	}
	nameDir := filepath.Join(root, key.Name)
	instDir := filepath.Join(nameDir, key.Instance)
	if _, err := files.Lstat(instDir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := checkUnder(owner, root, nameDir, instDir); err != nil {
		return err
	}
	if keep == "" {
		if err := files.RemoveAll(instDir); err != nil {
			return pluginmodel.PathRefusal(instDir, "cannot be removed")
		}
		// Only when empty: another instance of the plugin keeps it.
		_ = files.Remove(nameDir)
		return nil
	}
	des, err := files.ReadDir(instDir)
	if err != nil {
		return pluginmodel.PathRefusal(instDir, "cannot be read")
	}
	for _, de := range des {
		if de.Name() == keep {
			continue
		}
		p := filepath.Join(instDir, de.Name())
		if err := files.RemoveAll(p); err != nil {
			return pluginmodel.PathRefusal(p, "cannot be removed")
		}
	}
	return nil
}
