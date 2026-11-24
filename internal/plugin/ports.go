package plugin

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
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
// and the app hands it over in Ports. Every method takes the agent's handle and
// returns the database's errors unwrapped.
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
	// IsGuardError reports whether err is an error the guard raised.
	IsGuardError(err error) bool
	// DBError reads err as the database's own reply (a Postgres error): its
	// SQLSTATE, message and detail; ok is false when err is not one.
	DBError(err error) (code, message, detail string, ok bool)
	// NoAnswer reports whether the driver says the database did not answer:
	// a connection that failed, a send safe to retry or a timeout.
	NoAnswer(err error) bool

	OpenPluginApproval(ctx context.Context, q Querier, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error)
	ReadPluginApproval(ctx context.Context, q Querier, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error)
	ReadPluginApprovals(ctx context.Context, q Querier) ([]guardmodel.PluginApprovalRecord, error)
	SubmitPluginApproval(ctx context.Context, q Querier, r guardmodel.PluginApprovalResponse) (time.Time, error)
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
	// returns the bytes that read returned. The plugin watch reads every
	// change through it, never a second plain read.
	ReadConfig func(euid int, path string) (config.Config, []byte, error)
	// NewUnitHost is the plugin units an engine on host expects (HostFor).
	NewUnitHost func(host servicespec.PluginHost) UnitHost
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
func NewKeptAgent(db Querier, host string, port uint16, database, role string) KeptAgent {
	return KeptAgent{db: db, host: host, port: port, database: database, role: role}
}

// NewRequests serve the agents' request_plugin calls: uids is every
// configured agent's OS user id, admitted the OS users that may change
// plugins.
func NewRequests(uids map[string]uint32, admitted []uint32) *Requests {
	return &Requests{uids: uids, admitted: admitted}
}

// SetKept gives the requests the engine's kept plugins once the agents serve.
func (p *Requests) SetKept(k *KeptPlugins) { p.kept.Store(k) }
