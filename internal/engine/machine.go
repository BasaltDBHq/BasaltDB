package engine

import (
	"net"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Machine is the engine's reach into the files of this machine: its
// folders, its lock files, the agents' sockets in a folder and the record
// of why the supervisor gave up. engine/out/engineos is the real one.
type Machine interface {
	// MakeDirs makes dir and any missing parents with mode.
	MakeDirs(dir string, mode os.FileMode) error
	// MakePrivateDirs makes each of dirs with mode, and tightens one euid
	// owns that has more than mode; a symlink or a file is refused.
	MakePrivateDirs(euid int, mode os.FileMode, dirs ...string) error
	// StatPath is nil when path names a file, following links.
	StatPath(path string) error
	// Lstat describes path itself.
	Lstat(path string) (os.FileInfo, error)
	// RemoveFile removes the file at path.
	RemoveFile(path string) error
	// LockFile takes the exclusive lock on path without waiting:
	// config.ErrLocked when another process holds it.
	LockFile(path string) (release func(), err error)
	// LockHolderRuns is true when a live process holds the pid lock at path.
	LockHolderRuns(path string) bool
	// SocketFiles are the names of the sockets in dir.
	SocketFiles(dir string) []string
	// ReadLastStop reads the supervisor's record at path, as text to show;
	// false when there is no usable record.
	ReadLastStop(path string) (guidance.LastStop, bool)
}

// Sockets are the agents' listening sockets.
type Sockets interface {
	// ListenSocket listens on path, replacing a stale socket file but never
	// any other kind of file, and opens the socket to local users.
	ListenSocket(path string) (*net.UnixListener, error)
	// TemporaryAccept reports an accept error that passes (out of file
	// descriptors or memory, an aborted connection).
	TemporaryAccept(err error) bool
}

// ReadLastStop reads why the supervisor gave up, from dir (the state
// directory): ok is false when there is no usable record. It is read as
// text and shown, never trusted for anything else.
func ReadLastStop(m Machine, dir string) (guidance.LastStop, bool) {
	return m.ReadLastStop(filepath.Join(dir, LastStopFile))
}

// LastStopReader is ReadLastStop on m.
func LastStopReader(m Machine) func(dir string) (guidance.LastStop, bool) {
	return func(dir string) (guidance.LastStop, bool) { return ReadLastStop(m, dir) }
}
