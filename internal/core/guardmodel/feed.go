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
	ServedFrom(ctx context.Context, name, instance string, after int64) (int64, bool, error)
	SeqRetired(ctx context.Context, seq int64) (bool, error)
	ReadFeedRows(ctx context.Context, after int64, limit int) ([]FeedRow, error)
	OldestSeqAfter(ctx context.Context, after int64) (int64, bool, error)
}
