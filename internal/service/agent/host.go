package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// Host is what the agent takes from the adapters it may not import: the
// error values it tells apart, and the functions that read the host (the
// service manager, the crash directory, the Vault session). The app fills
// it once at start, before any tool is served, with UseHost. A function
// the app leaves nil is a build defect: its first use panics.
type Host struct {
	// StartCommand and RestartArgs are the service manager's start command
	// and restart command line for goos.
	StartCommand func(goos string) string
	RestartArgs  func(goos string) []string

	// StartHoldOffUntil is when the supervisor tries the engine again after
	// it gave up (false when it holds nothing off).
	StartHoldOffUntil func(stop LastStop, configPath string, now time.Time) (time.Time, bool)

	// CrashReports are the crash reports in dirs, newest first.
	CrashReports func(dirs ...string) []CrashReport

	// VaultConflict reports whether err is the Vault's answer that another
	// engine holds a link's token. ErrVaultNotConnected is what a relay
	// answers when no Vault is connected. AfterAnswer runs f after the
	// answer of the Vault session ctx belongs to (false: there is none).
	// RotateSession moves that session onto token.
	VaultConflict        func(err error) bool
	ErrVaultNotConnected error
	AfterAnswer          func(ctx context.Context, f func()) bool
	RotateSession        func(ctx context.Context, token channel.LinkToken) bool

	// RowTooLarge says whether err is one row over the result budget on its
	// own, with its message.
	RowTooLarge func(err error) (message string, ok bool)

	// ErrRevertNotFound, ErrApprovalNotFound and ErrInvalidParams are the
	// ledger's, ErrInvalidIntent the guard's: values the agent maps to
	// tool errors.
	ErrRevertNotFound   error
	ErrApprovalNotFound error
	ErrInvalidParams    error
	ErrInvalidIntent    error
	// ApprovalSortSpec whitelists the approval list sort.
	ApprovalSortSpec pagination.SortSpec

	// Record is the wire record of one change and its rows, as the ledger
	// renders it.
	Record func(ch action.Change, rows []action.RowChange) any

	// PluginApprovalsVersion is the basalt_meta version that holds plugin
	// approvals.
	PluginApprovalsVersion int

	// LatestGuardVersion is the basalt_meta version this build installs.
	LatestGuardVersion func() int

	// UpdateMessage is the notice for the agent to relay, for the binary
	// at exe.
	UpdateMessage func(n UpdateNotice, exe string) string
}

var host atomic.Pointer[Host]

// UseHost sets what the agent takes from the adapters. The app calls it
// once, before it serves any tool.
func UseHost(h Host) { host.Store(&h) }

func theHost() *Host {
	if h := host.Load(); h != nil {
		return h
	}
	panic("agent: host not set (internal/app sets it at start)")
}

// sentinel reports whether err is target, false for a target the host did
// not set.
func sentinel(err, target error) bool { return target != nil && errors.Is(err, target) }

// CrashReport is a crash report the engine saved: what status shows of it.
type CrashReport struct {
	ID      string
	Time    time.Time
	Version string
	Command string
	// IssueURL is the link that opens a prefilled issue, at most limit
	// characters long; "" when none fits.
	IssueURL func(limit int) string
}

// UpdateNotice is a newer release the engine knows of.
type UpdateNotice struct {
	Current  string
	Latest   string
	Security bool
	URL      string
}

// EngineRecord is this engine's row in the agent's database: its identity
// and whether it was revoked.
type EngineRecord struct {
	RecordedAt time.Time
	RevokedAt  *time.Time
}

// The statuses of the ledger's approvals and reverts, as the database
// keeps them.
const (
	approvalPending  = "PENDING"
	approvalApproved = "APPROVED"
	approvalApplied  = "APPLIED"
	approvalExpired  = "EXPIRED"

	revertPending  = "PENDING"
	revertApplying = "APPLYING"
	revertApplied  = "APPLIED"
	revertRejected = "REJECTED"
	revertExpired  = "EXPIRED"
)

// The Vault connection's states in status.vault.state.
const (
	vaultStateOff       = "OFF"
	vaultStateConnected = "CONNECTED"
	vaultStateKeyError  = "KEY_ERROR"
)

// The catalog's own types: what describe reads of the database's tables
// and views.

// CatalogRelation is one table, view, materialized view or partitioned
// table the session's role can read. Partitions are never listed on their
// own.
type CatalogRelation struct {
	OID    uint32
	Schema string
	Name   string
	// Kind is TABLE, VIEW, MATERIALIZED_VIEW or PARTITIONED_TABLE.
	Kind string
	// EstimatedRows is nil when the relation was never analyzed.
	EstimatedRows *int64
	// Comment is the catalog text, untrimmed.
	Comment string
	// Privileges lists SELECT, INSERT, UPDATE and DELETE as held by
	// session_user.
	Privileges []string
}

// CatalogColumn is one column of a relation. Selectable is false so the
// caller can count what it hides; it must not show them.
type CatalogColumn struct {
	Attnum int16
	Name   string
	// Type is the text format_type prints.
	Type     string
	Nullable bool
	// Default is the pg_get_expr text, empty when there is none.
	Default string
	// DefaultAttnums are the columns the default or generated expression reads.
	DefaultAttnums []int16
	Generated      bool
	Comment        string
	// Selectable is has_column_privilege(session_user, ..., 'SELECT').
	Selectable bool
}

// CatalogIndex is one index of a relation.
type CatalogIndex struct {
	Name       string
	Definition string
	// Attnums are the key and INCLUDE columns plus the columns read by
	// expressions and the predicate.
	Attnums   []int16
	Unique    bool
	Partial   bool
	SizeBytes int64
	Scans     int64
}

// CatalogKey is one foreign key touching a relation, seen from that
// relation.
type CatalogKey struct {
	Name     string
	Outgoing bool
	// Attnums are the key columns on this relation.
	Attnums  []int16
	OtherOID uint32
	// OtherSchema, OtherTable and OtherColumns are empty when the other
	// relation is not readable by session_user: a hidden table is counted,
	// never named.
	OtherSchema   string
	OtherTable    string
	OtherColumns  []string
	OtherReadable bool
	// OnDelete and OnUpdate are CASCADE, SET NULL, SET DEFAULT, RESTRICT or
	// NO ACTION.
	OnDelete string
	OnUpdate string
}

// CatalogStats is the size and scan activity of a relation. LastAnalyzed is
// nil when it never was.
type CatalogStats struct {
	TableBytes   int64
	TotalBytes   int64
	SeqScans     int64
	IndexScans   int64
	LastAnalyzed *time.Time
}

// CatalogDetail is everything describe reports about one relation.
type CatalogDetail struct {
	CatalogRelation
	Columns    []CatalogColumn
	PrimaryKey []int16
	Indexes    []CatalogIndex
	Keys       []CatalogKey
	Stats      CatalogStats
	RLS        bool
	// CascadesIntoHidden is how many distinct unreadable tables a DELETE here
	// reaches, transitively over CASCADE, SET NULL and SET DEFAULT.
	CascadesIntoHidden int
}

// CatalogMatch is one relation a search matched.
type CatalogMatch struct {
	CatalogRelation
	Rank int
	// Matched is "table", "schema", "column <name>" or "comment".
	Matched string
}

// CatalogSearchCursor is the last match of a page; the next page starts
// after it.
type CatalogSearchCursor struct {
	Rank   int
	Schema string
	Name   string
}

// CatalogColumnKey names one column by table OID and attribute number.
type CatalogColumnKey struct {
	OID    uint32
	Attnum int16
}

// CatalogAccess is what the agent's role can read and write, as quoted
// table names.
type CatalogAccess struct {
	Read       []string
	Write      []string
	NotGranted []string
}
