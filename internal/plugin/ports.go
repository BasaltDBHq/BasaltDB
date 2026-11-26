package plugin

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// Querier is an agent's database handle: a connection or a pool. It is opaque
// here, so the host links no database driver: the engine never runs SQL
// itself; it hands the handle to the Guard, whose adapter knows its type.
type Querier = any

// Guard is the port to the guard in an agent's database, where the plugin
// records, the approvals of plugin entries and the feed's events are kept. An
// outbound adapter implements it (platform/postgres/pluginledger)
// and the app hands it over in Ports. Every method takes the agent's handle.
// An error the store answered is a *pluginmodel.StoreError, its reason
// mapped by the adapter per call, wrapping the store's own error; an error
// the store did not answer is returned as the driver gave it (NoAnswer).
type Guard interface {
	// AgentVersion is the newest basalt_meta version installed.
	AgentVersion(ctx context.Context, q Querier) (int, error)
	// AgentStatus is the guard against this build's migrations.
	AgentStatus(ctx context.Context, q Querier) (guardmodel.Status, error)
	// InstallID is the install's id; the error is guardmodel.ErrNoInstall
	// when there is none.
	InstallID(ctx context.Context, q Querier) (uuid.UUID, error)
	// PluginApprovalsVersion is the basalt_meta version that holds plugin
	// approvals.
	PluginApprovalsVersion() int
	// Kind is the kind of store the agents' ledgers are in, as the feed's
	// events name it.
	Kind() action.StoreKind
	// NoAnswer reports whether the driver says the database did not answer:
	// a connection that failed, a send safe to retry or a timeout.
	NoAnswer(err error) bool

	OpenPluginApproval(ctx context.Context, q Querier, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error)
	ReadPluginApprovals(ctx context.Context, q Querier) ([]guardmodel.PluginApprovalRecord, error)
	PluginSettingsSHA256(ctx context.Context, q Querier, s guardmodel.PluginSettings) (string, error)

	RecordPluginEntryEvent(ctx context.Context, q Querier, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error
	RecordPluginTrustAdded(ctx context.Context, q Querier, keyID string) error
	RecordPluginTrustRemoved(ctx context.Context, q Querier, keyID string) error
	ReadPluginRecords(ctx context.Context, q Querier) (guardmodel.PluginRecords, error)

	// ReadSnapshot runs fn in one read-only snapshot of the database: one
	// repeatable-read transaction. It fails when q cannot begin one.
	ReadSnapshot(ctx context.Context, q Querier, fn func(guardmodel.FeedSnapshot) error) error
}

// Ports are the adapters the engine's plugin host is built on. The app fills
// them in Options (and in the ledgers and kept plugins it hands over); a
// missing one is refused when the host is built.
type Ports struct {
	Guard Guard
	// InGroup is whether an OS user is in a group.
	InGroup func(user, group string) (bool, error)
	// SystemdOverrides are the drop-ins systemd reads for a unit on this
	// machine (Linux only).
	SystemdOverrides func(unit string) ([]string, error)
	// ReadConfig reads engine.json at path exactly as the engine's start
	// read it, for a process with effective uid euid (as root, the hardened
	// read: no link followed, the file's owner and mode checked), and
	// returns the bytes that read returned: nil when it refused or could not
	// read the file, set with the error when the file was read and does not
	// parse or breaks a rule. The plugin package reads engine.json through it
	// only, never with a plain read.
	ReadConfig func(euid int, path string) (config.Config, []byte, error)
	// NewUnitHost is the plugin units an engine on host expects (HostFor).
	NewUnitHost func(host servicespec.PluginHost) UnitHost
	// WriteFeedCursor writes a feed cursor file whole: raw as name in dir,
	// which it makes when missing, mode 0600, without syncing dir.
	WriteFeedCursor func(dir, name string, raw []byte) error
	// ReadFeedCursor reads the feed cursor file name in dir whole.
	ReadFeedCursor func(dir, name string) ([]byte, error)
	// Files is the file system the engine's plugin host reads and writes.
	Files Files
}

// Files is the port to the file system: the plugin service does no file
// I/O itself (plugin/out/pluginfs implements it). Each method is the os call
// of the same name unless its comment says otherwise; the service keeps the
// steps, their order, the checks and the refusals. No open file reaches the
// service: a method that opens one does each step on that one open file and
// closes it, running the service's check on the open file's details (never
// on the path) before anything is read or written, so the file checked is
// the file read. A step that fails is an *fs.PathError whose Op names the
// step (opOpen, opStat, opRead, opCreate, opWrite); an error the check
// returns comes back as it is.
type Files interface {
	// OpenRoot opens dir once as an os.Root; every name is then resolved
	// inside it.
	OpenRoot(dir string) (FileRoot, error)
	// ReadOpen opens name with flag, Stats the open file, runs check on its
	// details (no Stat and no check when check is nil), reads up to most
	// bytes from it and closes it.
	ReadOpen(name string, flag int, most int64, check func(fs.FileInfo) error) ([]byte, error)
	// HashOpen opens name with flag, Stats the open file, runs check on its
	// details and returns the SHA-256 of the whole open file.
	HashOpen(name string, flag int, check func(fs.FileInfo) error) ([]byte, error)
	// WriteNew creates name, which must not exist (O_EXCL, mode), writes data
	// to it, sets mode on it, syncs it when sync is set and closes it.
	WriteNew(name string, data []byte, mode fs.FileMode, sync bool) error
	ReadFile(name string) ([]byte, error)
	Lstat(name string) (fs.FileInfo, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	// WalkDir is filepath.WalkDir.
	WalkDir(root string, fn fs.WalkDirFunc) error
	Mkdir(name string, perm fs.FileMode) error
	MkdirAll(name string, perm fs.FileMode) error
	MkdirTemp(dir, pattern string) (string, error)
	Chmod(name string, mode fs.FileMode) error
	Rename(oldpath, newpath string) error
	Remove(name string) error
	RemoveAll(name string) error
	// WriteAtomic writes raw whole as name: a temporary file renamed into
	// place with mode, and the directory synced after the rename when
	// syncDir is set.
	WriteAtomic(name string, raw []byte, mode fs.FileMode, syncDir bool) error
	// Lock takes an exclusive lock on name; the function releases it.
	Lock(name string) (func(), error)
	// NoFollow are the open flags that refuse a final symlink and do not
	// block on a FIFO or a device.
	NoFollow() int
	// Owner is the uid that owns the file fi describes; false when fi
	// carries none.
	Owner(fi fs.FileInfo) (uint32, bool)
	// Links is the hard link count of the file fi describes; false when fi
	// carries none.
	Links(fi fs.FileInfo) (uint64, bool)
}

// FileRoot is a directory Files.OpenRoot opened once: every name is resolved
// inside it, and each method opens, uses and closes its file within the
// call. It is an alias of an interface literal, the same literal as
// pluginfs.FileRoot, so the adapter satisfies Files without importing this
// package.
type FileRoot = interface {
	// Lstat is os.Root.Lstat.
	Lstat(name string) (fs.FileInfo, error)
	// Mkdir is os.Root.Mkdir.
	Mkdir(name string, perm fs.FileMode) error
	// Chmod is os.Root.Chmod.
	Chmod(name string, mode fs.FileMode) error
	// ReadOpen is Files.ReadOpen on name inside the root.
	ReadOpen(name string, flag int, most int64, check func(fs.FileInfo) error) ([]byte, error)
	// CopyOut opens name inside the root with flag and Stats that open
	// file; check gets its details and returns the mode of the copy. It
	// then creates dst (outside the root, O_EXCL, perm), copies the open
	// file into it, sets mode on the new file, syncs and closes it.
	CopyOut(name string, flag int, check func(fs.FileInfo) (fs.FileMode, error), dst string, perm fs.FileMode) error
	// WriteOpen opens name inside the root with flag and perm, Stats that
	// open file, runs check on its details and, when check passes, writes
	// data to it.
	WriteOpen(name string, flag int, perm fs.FileMode, check func(fs.FileInfo) error, data []byte) error
	// Close closes the root.
	Close() error
}

// The steps a Files or FileRoot method names in the Op of the *fs.PathError it
// returns: the same strings as pluginfs.OpOpen and the rest.
const (
	opOpen   = "open"
	opStat   = "stat"
	opRead   = "read"
	opCreate = "create"
	opWrite  = "write"
)

// failedStep is the step an open-file method failed in, "" when err is no
// step's failure (an error the service's own check returned).
func failedStep(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op
	}
	return ""
}

// UnitHost is the plugin units a service engine expects: the OS service
// adapter renders them.
type UnitHost interface {
	// EngineUser is the OS user the engine runs as; its group reaches the
	// plugins' socket directories.
	EngineUser() string
	// RenderUnit is the unit local entry e needs: its file and its names.
	// It fails when the entry's names or unit cannot be rendered.
	RenderUnit(e servicespec.PluginEntry) (pluginmodel.UnitPlan, error)
	// UserInGroup says that the plugin's OS user is in the engine's group
	// and how to take it out.
	UserInGroup(pluginUser string) string
}

// Dialer reaches an entry's plugin: the transports are outbound adapters.
type Dialer interface {
	// Entry starts or connects to the entry (same-user mode, remote).
	Entry(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, socketBase, credentialFile string, stderr io.Writer) (pluginmodel.Transport, error)
	// Service connects to the entry's unit on its socket (service mode).
	Service(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, socket string, uid, gid uint32, recheck func() error) (pluginmodel.Transport, error)
	// NoSocket and SocketDir say why Service failed: nothing listens on the
	// socket, or its directory is not the unit's.
	NoSocket(err error) bool
	SocketDir(err error) bool
}

// check names a port that is missing, "" when none is.
func (p Ports) check() string {
	switch {
	case p.Guard == nil:
		return "Guard"
	case p.InGroup == nil:
		return "InGroup"
	case p.SystemdOverrides == nil:
		return "SystemdOverrides"
	case p.NewUnitHost == nil:
		return "NewUnitHost"
	case p.ReadConfig == nil:
		return "ReadConfig"
	case p.WriteFeedCursor == nil:
		return "WriteFeedCursor"
	case p.ReadFeedCursor == nil:
		return "ReadFeedCursor"
	case p.Files == nil:
		return "Files"
	}
	return ""
}

// approvalsVersion is the basalt_meta version that holds plugin approvals.
func (p Ports) approvalsVersion() int { return p.Guard.PluginApprovalsVersion() }

// NewOptions are the options of an engine run: stderr receives local plugins'
// stderr (nil discards it), euid is the engine's user id, stateDir is where
// it keeps its state ("" feeds no plugin), kept is a service engine's own
// entries (nil in same-user mode) and dialer reaches the entries.
func NewOptions(stderr io.Writer, euid int, stateDir string, kept *Store, dialer Dialer, ports Ports) Options {
	return Options{Stderr: stderr, euid: euid, stateDir: stateDir, kept: kept, Dialer: dialer, Ports: ports}
}

// NewAgentLedger is an agent's ledger for the plugin records: its database
// handle, the engine's admission of the agent (nil admits it) and the ports.
func NewAgentLedger(db Querier, admit func(context.Context) error, ports Ports) AgentLedger {
	return AgentLedger{db: db, admit: admit, ports: ports}
}

// NewKeptAgent is an agent as the plugin methods reach it: its database
// handle and where that is.
func NewKeptAgent(db Querier, host string, port uint16, database string) KeptAgent {
	return KeptAgent{db: db, host: host, port: port, database: database}
}

// NewRequests serve the agents' request_plugin calls: uids is every
// configured agent's OS user id, admitted the OS users that may change
// plugins.
func NewRequests(uids map[string]uint32, admitted []uint32) *Requests {
	return &Requests{uids: uids, admitted: admitted}
}

// SetKept gives the requests the engine's kept plugins once the agents serve.
func (p *Requests) SetKept(k *KeptPlugins) { p.kept.Store(k) }

// PluginApprovalStore is the guard's plugin approvals on the agent's own
// credential (schema version Plugin.ApprovalsVersion).
type PluginApprovalStore interface {
	// ReadPluginApproval is one plugin approval the role may see, and false
	// when there is none. Its texts are set only for the role that opened
	// it.
	ReadPluginApproval(ctx context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error)
	// SubmitPluginApproval relays the person's assertion; the guard
	// verifies it and records the approval. A refusal is a
	// *pluginmodel.ApprovalRefusalError.
	SubmitPluginApproval(ctx context.Context, r guardmodel.PluginApprovalResponse) (time.Time, error)
}

// PathRules is the port for the path rule: who may write the directories and
// files the host trusts (CONTRACT.md, Plugins, Where plugins live). The rule
// reads the file system, so an outbound adapter (plugin/out/pluginpath)
// implements it and the app installs it with UsePathRules.
type PathRules interface {
	// Owner is the uid the rule requires for mode.
	Owner(mode pluginmodel.Mode) (uint32, error)
	// CurrentUID is the engine's own uid.
	CurrentUID() (uint32, error)
	// NoFollowFlags are the flags to open a file without following a symlink.
	NoFollowFlags() int
	// RuleRefusal is a refusal for who can write path, with what was found.
	RuleRefusal(path, why string, kind pluginmodel.PathFaultKind, fi fs.FileInfo, owners ...uint32) *pluginmodel.VerifyError
	CheckAbove(base string, owner uint32) error
	CheckStrict(p string, owner uint32) (fs.FileInfo, error)
	CheckStrictInfo(p string, fi fs.FileInfo, owner uint32) error
	CheckUnder(owner uint32, dirs ...string) error
	CheckSocketBase(dir string) error
	CheckSocketBaseInfo(dir string, fi fs.FileInfo) error
}

// PluginRequests serve request_plugin with the engine's engine-kept plugin
// entries (CONTRACT.md, Plugin approval in service mode). caller is the
// agent that calls; every method applies its OS user's scope. Errors are
// *PluginRefusedError, ErrPluginNotFound or *ArgumentError; anything else is
// INTERNAL.
type PluginRequests interface {
	// OpenPlugin is PLUGIN_OPEN for caller: the uploaded copy, or the
	// installed one when p.UploadID is nil.
	OpenPlugin(ctx context.Context, caller string, p PluginOpen) (PluginOpened, error)
	// RemovePlugin is PLUGIN_REMOVE for caller.
	RemovePlugin(ctx context.Context, caller, name, instance string) error
	// PluginApproval is the state of approval id, as PLUGIN_LIST shows the
	// entry that holds it to caller, and what the engine serves of it.
	PluginApproval(ctx context.Context, caller string, id uuid.UUID) (PluginApprovalState, error)
	// DropUpload removes caller's upload id of a call refused before the
	// engine took it, so no refusal holds one of its few open uploads.
	DropUpload(caller string, id uuid.UUID)
}

// Delivery is what the plugin use case asks of the delivery use case.
type Delivery interface {
	CredentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	IssuedLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error)
	RelayLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) string
	RelayConnected() bool
	PollInterval() time.Duration
}

// StatusView is what the plugin use case reads of the status use case.
type StatusView interface {
	// SameUser says the engine runs as the person's own OS user.
	SameUser() bool
	// DevLocalPages says engine.json has devLocalPages set.
	DevLocalPages() bool
	// VaultState is the engine's Vault state, status.VaultOff when there is
	// no Vault reporter.
	VaultState() string
	// GuardStatus reads the guard's state on the agent's credential.
	GuardStatus(ctx context.Context) (guardmodel.Status, error)
}

// Admitter admits a call: the engine is set up and its guard is current.
type Admitter interface {
	Admit(ctx context.Context) error
}

// Clock is the time the supervisor waits on: the health interval and the
// restart backoff. Each call keeps its own deadline on the real clock.
type Clock interface {
	// After returns a channel that receives once d has passed.
	After(d time.Duration) <-chan time.Time
}

// Exiter is a transport to a local process: Exited is closed once the
// process has exited. The supervisor uses it to give a plugin that
// answered shutdown the time to exit before its process group is killed.
type Exiter interface {
	Exited() <-chan struct{}
}

// PluginUploadChannel is the agent's side of a plugin upload: it reads the
// plugin folder as the agent's OS user and sends it to the engine over the
// agent's own socket (the shim implements it).
type PluginUploadChannel interface {
	// ReadSource reads the plugin folder dir for an upload.
	ReadSource(dir string) (UploadSource, error)
	// Upload sends files to the engine as one upload and returns its id.
	Upload(ctx context.Context, files []UploadFile) (uploadID string, err error)
}
