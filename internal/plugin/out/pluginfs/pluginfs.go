// Package pluginfs is the plugin host's file system: the outbound adapter
// behind plugin.Files. Each method is the os call of the same name, or the
// one named in its comment, with nothing added: the plugin service keeps
// the steps, their order, the checks and the refusals. The methods that
// open a file (open.go) do every step on that one open file inside the
// call and never hand the file out; the service's check runs on the open
// file's details before anything is read or written.
package pluginfs

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

// Files is the plugin host's file system on this machine.
type Files struct{}

func (Files) ReadFile(name string) ([]byte, error)          { return os.ReadFile(name) }
func (Files) Lstat(name string) (fs.FileInfo, error)        { return os.Lstat(name) }
func (Files) ReadDir(name string) ([]fs.DirEntry, error)    { return os.ReadDir(name) }
func (Files) WalkDir(root string, fn fs.WalkDirFunc) error  { return filepath.WalkDir(root, fn) }
func (Files) Mkdir(name string, perm fs.FileMode) error     { return os.Mkdir(name, perm) }
func (Files) MkdirAll(name string, perm fs.FileMode) error  { return os.MkdirAll(name, perm) }
func (Files) Chmod(name string, mode fs.FileMode) error     { return os.Chmod(name, mode) }
func (Files) Rename(oldpath, newpath string) error          { return os.Rename(oldpath, newpath) }
func (Files) Remove(name string) error                      { return os.Remove(name) }
func (Files) RemoveAll(name string) error                   { return os.RemoveAll(name) }
func (Files) MkdirTemp(dir, pattern string) (string, error) { return os.MkdirTemp(dir, pattern) }

// WriteAtomic is atomicfile.Write: raw whole as name, a temporary file
// renamed into place with mode, the directory synced after the rename when
// syncDir is set.
func (Files) WriteAtomic(name string, raw []byte, mode fs.FileMode, syncDir bool) error {
	return atomicfile.Write(name, raw, atomicfile.Options{Mode: mode, SyncDir: syncDir})
}

// Lock is config.LockFile: an exclusive lock on name, released by the
// function it returns.
func (Files) Lock(name string) (func(), error) { return config.LockFile(name) }
