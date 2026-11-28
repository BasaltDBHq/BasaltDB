// Package servicespec is the data of the engine service that the use cases
// name and the OS adapters act on: the service spec and the files the
// install writes, the unit names, the administrator dialog's prompts and
// outcomes, a crash handler's input, the last-stop record, and the plugin
// units' entries, hosts, names and OS users.
package servicespec

import (
	"errors"
	"time"
)

// Service names.
const (
	SystemdUnitName = "basalt-engine.service"
	LaunchdLabel    = "dev.basaltdb.engine"
	// RemovalMarkerName is the file the engine creates in its state folder
	// to ask the removal job to remove it from this computer.
	RemovalMarkerName = "remove-requested"
)

// Errors of an administrator dialog run.
var (
	// ErrNoDialog: no administrator dialog can be shown here (an SSH
	// session, a machine without a desktop).
	ErrNoDialog = errors.New("no administrator dialog is available here")
	// ErrDialogCancelled: the person closed the dialog.
	ErrDialogCancelled = errors.New("the administrator dialog was cancelled")
)

// The fixed prompts the macOS administrator dialog shows for each action,
// so a dialog the person did not expect names what it would do in its
// first sentence. Only macOS shows them (pkexec shows polkit's own text). They are
// constants: no value from the agent, the engine or the environment
// reaches them.
const (
	InstallPrompt = "BasaltDB wants to install its engine on this Mac. It copies basalt into a system folder, creates the engine's own system account and folders and starts the engine. Cancel unless you just asked to set up BasaltDB."
	RestartPrompt = "BasaltDB wants to restart its engine on this Mac. The engine runs another build than the basalt you just ran, so it copies that basalt into a system folder and restarts the engine onto it. Cancel unless you just installed or upgraded BasaltDB."
	ResetPrompt   = "BasaltDB wants to reset its engine on this Mac. It deletes the engine's config and credentials. Cancel unless you just answered 'No, this isn't mine' on the setup page."
)

// Kinds of crash.
const (
	CrashKindPanic = "PANIC"
	CrashKindFatal = "FATAL"
)

// CrashDirName is the directory, under the state directory, that holds the
// crash reports.
const CrashDirName = "crash"

// MaxCredentialBytes bounds a credential: the connection string service
// install reads from stdin and a credential file it reads back.
const MaxCredentialBytes = 4096

// ErrCrashNotPruned is a crash save's error when the report was written but
// older reports could not all be deleted: the report's id is good.
var ErrCrashNotPruned = errors.New("older crash reports were not deleted")

// CrashInput is what a crash handler knows.
type CrashInput struct {
	// Command is the command or tool name; anything not shaped like one is
	// saved as "unknown".
	Command   string
	Kind      string
	ErrorCode string
	// Value is the recovered panic value.
	Value any
	// Stack is runtime/debug.Stack from the deferred handler.
	Stack []byte
}

// LastStopFileRecord is last-stop.json: why the supervisor gave up, when,
// and the SHA-256 of engine.json at that moment.
type LastStopFileRecord struct {
	Reason       string    `json:"reason"`
	At           time.Time `json:"at"`
	EngineSHA256 string    `json:"engineSha256,omitempty"`
}
