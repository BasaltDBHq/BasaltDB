//go:build unix

package atomicfile

import "os"

// SyncDir flushes a change to dir's entries (a new name, a rename) to disk.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
