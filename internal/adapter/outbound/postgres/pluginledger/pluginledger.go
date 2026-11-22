// Package pluginledger is the guard's plugin records, approvals and feed
// reads as the plugin host's ledger port (engine.Guard).
package pluginledger

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

type q = pgquerier.Querier

// Ledger forwards each call to the guard package. It holds no state.
type Ledger struct{}

func (Ledger) AgentVersion(ctx context.Context, db q) (int, error) {
	return guard.AgentVersion(ctx, db)
}

func (Ledger) AgentStatus(ctx context.Context, db q) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, db, guard.Migrations())
}

func (Ledger) InstallID(ctx context.Context, db q) (uuid.UUID, error) {
	return guard.InstallID(ctx, db)
}

func (Ledger) PluginApprovalsVersion() int { return guard.PluginApprovalsVersion }

func (Ledger) IsGuardError(err error) bool {
	_, ok := guard.CodeOf(err)
	return ok
}

func (Ledger) OpenPluginApproval(ctx context.Context, db q, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error) {
	return guard.OpenPluginApproval(ctx, db, d, s)
}

func (Ledger) EndPluginApproval(ctx context.Context, db q, name, instance string) error {
	return guard.EndPluginApproval(ctx, db, name, instance)
}

func (Ledger) ReadPluginApproval(ctx context.Context, db q, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	return guard.ReadPluginApproval(ctx, db, id)
}

func (Ledger) ReadPluginApprovals(ctx context.Context, db q) ([]guardmodel.PluginApprovalRecord, error) {
	return guard.ReadPluginApprovals(ctx, db)
}

func (Ledger) SubmitPluginApproval(ctx context.Context, db q, r guardmodel.PluginApprovalResponse) (time.Time, error) {
	return guard.SubmitPluginApproval(ctx, db, r)
}

func (Ledger) PluginSettingsSHA256(ctx context.Context, db q, s guardmodel.PluginSettings) (string, error) {
	return guard.PluginSettingsSHA256(ctx, db, s)
}

func (Ledger) RecordPluginEntryEvent(ctx context.Context, db q, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error {
	return guard.RecordPluginEntryEvent(ctx, db, kind, d)
}

func (Ledger) RecordPluginTrustAdded(ctx context.Context, db q, keyID string) error {
	return guard.RecordPluginTrustAdded(ctx, db, keyID)
}

func (Ledger) RecordPluginTrustRemoved(ctx context.Context, db q, keyID string) error {
	return guard.RecordPluginTrustRemoved(ctx, db, keyID)
}

func (Ledger) ReadPluginRecords(ctx context.Context, db q) (guardmodel.PluginRecords, error) {
	return guard.ReadPluginRecords(ctx, db)
}

// ReadSnapshot runs fn in one read-only repeatable-read transaction.
func (Ledger) ReadSnapshot(ctx context.Context, db q, fn func(guardmodel.FeedSnapshot) error) error {
	b, ok := db.(guard.TxBeginner)
	if !ok {
		return errors.New("the agent's connection cannot take a transaction")
	}
	return pgx.BeginTxFunc(ctx, b, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return fn(snapshot{tx: tx})
	})
}

type snapshot struct{ tx pgx.Tx }

func (s snapshot) InstallID(ctx context.Context) (uuid.UUID, error) {
	return guard.InstallID(ctx, s.tx)
}

func (s snapshot) ChainHeadSeq(ctx context.Context) (int64, error) {
	return guard.ChainHeadSeq(ctx, s.tx)
}

func (s snapshot) ServedFrom(ctx context.Context, name, instance string, after int64) (int64, bool, error) {
	return guard.ServedFrom(ctx, s.tx, name, instance, after)
}

func (s snapshot) SeqRetired(ctx context.Context, seq int64) (bool, error) {
	return guard.SeqRetired(ctx, s.tx, seq)
}

func (s snapshot) ReadFeedRows(ctx context.Context, after int64, limit int) ([]guardmodel.FeedRow, error) {
	return guard.ReadFeedRows(ctx, s.tx, after, limit)
}

func (s snapshot) OldestSeqAfter(ctx context.Context, after int64) (int64, bool, error) {
	return guard.OldestSeqAfter(ctx, s.tx, after)
}
