// Package engineos is the engine's reach into the machine (engine.Machine,
// engine.Sockets and engine.StarterOS): its folders and lock files, the
// agents' sockets, the supervisor basalt mcp launches and the record of
// why the supervisor gave up.
package engineos

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
)

// OS is the real machine.
type OS struct{}

// MakeDirs makes dir and any missing parents with mode (os.MkdirAll).
func (OS) MakeDirs(dir string, mode os.FileMode) error { return os.MkdirAll(dir, mode) }

// StatPath is nil when path names a file, following links; the stat error
// otherwise.
func (OS) StatPath(path string) error {
	_, err := os.Stat(path)
	return err
}

// Lstat describes path itself, never what a link at path points at.
func (OS) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }

// RemoveFile removes the file at path.
func (OS) RemoveFile(path string) error { return os.Remove(path) }

// LockFile takes the exclusive lock on path without waiting
// (config.LockFile): config.ErrLocked when another process holds it.
func (OS) LockFile(path string) (func(), error) { return config.LockFile(path) }

// LockHolderRuns is true when a live process holds the pid lock at path
// (pidlock.Running).
func (OS) LockHolderRuns(path string) bool {
	_, up, _ := pidlock.Running(path)
	return up
}

// SocketFiles are the names of the sockets in dir; none when dir cannot be
// read.
func (OS) SocketFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.Type()&os.ModeSocket != 0 {
			names = append(names, e.Name())
		}
	}
	return names
}
