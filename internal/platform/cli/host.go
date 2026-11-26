package cli

import (
	"context"
	"crypto/x509"
	"io"
	"os"
)

// Machine is what basalt init does on the machine beyond Postgres: elevate
// once with sudo for the service install, check the engine answers, and
// run claude mcp add. Tests replace it with a fake that records calls.
type Machine interface {
	// Euid is the effective user id (0 when init already runs as root).
	Euid() int
	// Executable is the absolute path of this basalt binary.
	Executable() (string, error)
	// UserConfigDir is the person's config directory (os.UserConfigDir).
	UserConfigDir() (string, error)
	// Sudo runs args under sudo with stdin, which carries the agent's
	// credential; sudo asks for the password on the terminal.
	Sudo(ctx context.Context, args []string, stdin string, out, errw io.Writer) error
	// ResolvedExecutable is this basalt binary's path with every link
	// resolved; an error when a link cannot be resolved.
	ResolvedExecutable() (string, error)
	// DialogAvailable says why the system's administrator dialog cannot be
	// shown here, or nil when it can (service.ErrNoDialog wrapped).
	DialogAvailable(goos string) error
	// AdminDialog asks the person, through the system's administrator
	// dialog showing prompt (one of service's fixed prompts), to run script
	// as root (service.DialogCommand), with a fixed environment and / as its
	// directory.
	AdminDialog(ctx context.Context, goos, prompt, script string, out io.Writer) error
	// SetupState posts an empty request to the engine's setup check route
	// at origin and returns the refusal code it answers: JOB_UNAVAILABLE
	// from an engine that has a config, another code from one waiting for
	// it. An error when nothing answers.
	SetupState(ctx context.Context, origin string) (string, error)
	// EngineBuild asks the engine's GET /healthz at origin for its build:
	// "" from an engine too old to say. An error when nothing answers.
	EngineBuild(ctx context.Context, origin string) (string, error)
	// LookPath finds a command on PATH.
	LookPath(name string) (string, error)
	// Run runs a command as the person.
	Run(ctx context.Context, args []string, out, errw io.Writer) error
	// System runs service install steps in this process (init as root).
	System(out, errw io.Writer) System
	// Probe waits until the engine answers MCP initialize on socket.
	Probe(ctx context.Context, socket string) error
	// EngineLog reads the end of the engine service's log on goos, when
	// the person may read it.
	EngineLog(ctx context.Context, goos string) (string, error)
	// OpenURL opens link in the person's default browser.
	OpenURL(ctx context.Context, link string) error
	// PagesUp reports whether the engine serves its local pages at origin.
	PagesUp(ctx context.Context, origin string) bool
	// ServiceRuns reads from the service manager how many times the engine
	// service started and its last exit code (-1 when it never exited).
	ServiceRuns(ctx context.Context, goos string) (runs, lastExit int, err error)
}

// System is what the service install steps do on the machine: the
// operating system's users, groups and files, and the commands it runs. It
// has the method set of the service install's System, so either is the
// other.
type System interface {
	UserExists(name string) bool
	// InGroup reports whether an OS user is in a group, as its primary or a
	// supplementary group; a group that does not exist has no one in it.
	InGroup(name, group string) (bool, error)
	// Exists reports whether a file exists (an installed unit).
	Exists(path string) bool
	Output(ctx context.Context, args ...string) (string, error)
	Run(ctx context.Context, args ...string) error
	// WriteFile writes a file without following links; owner, when set, is
	// the OS user that owns the new file.
	WriteFile(path string, data []byte, mode os.FileMode, owner string) error
	// CreateFile makes an empty file owned by owner with mode when it is
	// missing and keeps an existing one's content, without following a
	// link; it refuses a path that is not a plain file.
	CreateFile(path string, mode os.FileMode, owner string) error
	// MoveAside renames the directory at path, as a whole and without
	// following a link, to a new name next to it when the OS user owner
	// owns it, and returns that name ("" when left as it is).
	MoveAside(path, owner string) (string, error)
	// Mkdir makes a directory (or takes over an existing real one) without
	// following a link; group, when set, is its group instead of owner's.
	Mkdir(path string, mode os.FileMode, owner, group string) error
	Remove(path string) error
	// RemoveTree removes a directory and everything in it without
	// following a link; a missing one is not an error.
	RemoveTree(path string) error
	// CheckBinary refuses a binary anyone but root could change.
	CheckBinary(path string) error
}

// Host is what the CLI shell reaches outside itself: database
// connections, the trust profiles a connection uses and the hardened open
// of a config file. The shell names no adapter; app fills it.
type Host interface {
	// Connect opens one connection, usable through a transaction pooler.
	Connect(ctx context.Context, dsn string) (Conn, error)
	// WithCertificateHint is err with what can fix it, when it is a
	// certificate of dsn's host that did not verify.
	WithCertificateHint(dsn string, err error) error
	// CertificateNotVerified reports whether err is a server certificate
	// that did not verify.
	CertificateNotVerified(err error) bool
	// PinnedHost is dsn's host when the trust profile a connection opened
	// now uses for it is that host's pin; false otherwise, and for a
	// string the driver cannot parse.
	PinnedHost(dsn string) (PinnedHost, bool)
	// OSOpenTrustedFile opens path read-only for root, never through a
	// symlink, its directory trusted only from root or owner.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
}

// PinnedHost is a database host a trust profile pins: its name as pinned,
// its port, and the certificates it is pinned to.
type PinnedHost struct {
	Host  string
	Port  int
	Roots []*x509.Certificate
}
