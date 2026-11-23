package guardmodel

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// The ledger kinds a feed/1 event is made from (CONTRACT.md, Plugins,
// Notifier messages, Which ledger rows are events).
const (
	KindChange          = "CHANGE"
	KindRefused         = "REFUSED"
	KindApprovalPending = "APPROVAL_PENDING"
	KindApproved        = "APPROVED"
	KindRevertPending   = "REVERT_PENDING"
	KindRevertSigned    = "REVERT_SIGNED"
	KindReverted        = "REVERTED"
	KindRevertRejected  = "REVERT_REJECTED"
)

// FeedRow is one row of the calling agent's ledger that is a feed/1 event,
// with only the fields an event may carry, each as the row holds it (detail
// fields as text, nil when absent). It never holds an intent, a statement,
// params, a refusal's reason, a key or a value: they are not read.
type FeedRow struct {
	Seq          int64
	At           time.Time
	Kind         string
	ChangeID     uuid.NullUUID
	Op           *string
	RunID        *string
	TaskID       *string
	Table        *string
	Rows         *string
	CascadedRows *string
	ApprovalID   *string
	ExpiresAt    *string
	RevertID     *string
	Code         *string
}

// ErrNoInstall is the error of reading the install id when basalt_meta has no
// install row: the guard is not installed, or an install older than the id.
var ErrNoInstall = errors.New("basalt_meta has no install record; run basalt init again with the admin connection string")

// FeedSnapshot is what the feed reads from one agent's database inside one
// read-only snapshot (a port is written in it).
type FeedSnapshot interface {
	InstallID(ctx context.Context) (uuid.UUID, error)
	ChainHeadSeq(ctx context.Context) (int64, error)
	PluginEntryEvents(ctx context.Context, name, instance string) ([]PluginEntryEvent, error)
	SeqRetired(ctx context.Context, seq int64) (bool, error)
	ReadFeedRows(ctx context.Context, after int64, limit int, f FeedFilter) ([]FeedRow, error)
	OldestSeqAfter(ctx context.Context, after int64) (int64, bool, error)
}

// PluginEntryEvent is one PLUGIN_ENABLED, PLUGIN_CHANGED or PLUGIN_DISABLED
// record of an entry in the calling agent's ledger, with the egress and
// endpoint its detail names. DecodeErr is set when either does not decode.
type PluginEntryEvent struct {
	Seq       int64
	Kind      string
	Egress    []string
	Endpoint  PluginEndpoint
	DecodeErr bool
}

// FeedFilter is which ledger rows a feed read returns: rows of the listed
// kinds, a CHANGE only when it was applied (AppliedChangesOnly), and a
// REFUSED only when its op is not SELECT (SkipRefusedReads). The store
// applies it in its query, so a limit pages over the rows it keeps.
type FeedFilter struct {
	Kinds              []string
	AppliedChangesOnly bool
	SkipRefusedReads   bool
}
