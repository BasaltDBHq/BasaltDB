package engine

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Recorder saves this process's crash reports.
type Recorder interface {
	// SaveIn saves in as a report in dir, readable by the engine's group
	// when shared, and returns the report's id.
	SaveIn(dir string, shared bool, in servicespec.CrashInput) (id string, err error)
}

// Host is what the engine's use cases reach outside themselves.
type Host interface {
	CrashDirHost
	// NewRecorder is the crash recorder for this process.
	NewRecorder() Recorder
	// LastStopHashEngineJSON is the hash of the engine config at path that
	// a give-up records.
	LastStopHashEngineJSON(path string) string
}

// StarterHost is what the engine's starter reads of the last-stop record.
type StarterHost interface {
	// LastStopStartHoldOffUntil is when a give-up recorded as rec holds off
	// a new start of the engine at configPath until, as of now; false when
	// it does not.
	LastStopStartHoldOffUntil(rec servicespec.LastStopFileRecord, configPath string, now time.Time) (time.Time, bool)
}

// Terminal is what the engine's use cases read from the CLI shell, and the
// machine's files it reaches.
type Terminal interface {
	Machine
	// TerminalText is s safe to print on a terminal.
	TerminalText(s string) string
	// InfoOwnerUID is the owner of the file fi describes; false where the
	// platform has no owners.
	InfoOwnerUID(fi os.FileInfo) (int, bool)
	// WriteFileAtomic writes data to path so a reader sees the old file or
	// the new one, never part of it.
	WriteFileAtomic(path string, data []byte) error
	// HeldAtEveryLook is true when held is true at every one of a few looks,
	// sleep apart.
	HeldAtEveryLook(held func() bool, sleep func(time.Duration)) bool
	// LoadEngineConfigAs reads the engine config at path for a process with
	// effective uid euid: as root, the hardened read.
	LoadEngineConfigAs(euid int, path string) (config.Config, error)
}

// CrashDirHost is the machine's per-user config directory.
type CrashDirHost interface {
	UserConfigDir() (string, error)
}

// Gate admits the calls a server runs: Begin before each call, false when
// the call is answered as restarting and not run; End after each admitted
// call is answered.
type Gate interface {
	Begin() bool
	End()
}

// Server is an agent's MCP server: it serves one connection, each call
// admitted by gate.
type Server interface {
	ServeGated(ctx context.Context, in io.Reader, out io.Writer, gate Gate) error
}

// MCP writes the engine's lines in the MCP wire format.
type MCP interface {
	// WritePeerRefused writes the one line that refuses a peer of another
	// OS user.
	WritePeerRefused(w io.Writer, message string) error
}

// BinaryWatch finds the binary this process was started from.
type BinaryWatch interface {
	// ExecPath is the path this process was started from as arg0 names it,
	// looked up on PATH, and checked to be the running binary exe.
	ExecPath(arg0, exe string) (string, error)
}

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
