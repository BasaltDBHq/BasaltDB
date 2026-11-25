// Package pluginledger is the guard's plugin records, approvals and feed
// reads as the plugin host's guard port (engine.Guard).
package pluginledger

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
)

// q is the agent's database handle as the plugin host hands it over: opaque
// to the host, a pgx connection or pool here.
type q = any

// asPgx is the handle as the guard package takes it.
func asPgx(db q) pgquerier.Querier {
	c, ok := db.(pgquerier.Querier)
	if !ok {
		panic("pluginledger: the database handle is not a pgx connection, pool or transaction")
	}
	return c
}

// Ledger is engine.Guard: it forwards each call to the guard package and
// holds no state.
type Ledger struct{}

func (Ledger) AgentVersion(ctx context.Context, db q) (int, error) {
	return guard.AgentVersion(ctx, asPgx(db))
}

func (Ledger) AgentStatus(ctx context.Context, db q) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, asPgx(db), guard.Migrations())
}

func (Ledger) InstallID(ctx context.Context, db q) (uuid.UUID, error) {
	return guard.InstallID(ctx, asPgx(db))
}

func (Ledger) PluginApprovalsVersion() int { return guard.PluginApprovalsVersion }

func (Ledger) IsGuardError(err error) bool {
	_, ok := guard.CodeOf(err)
	return ok
}

// DBError reads err as the database's own reply: a Postgres error.
func (Ledger) DBError(err error) (code, message, detail string, ok bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", "", "", false
	}
	return pg.Code, pg.Message, pg.Detail, true
}

// NoAnswer reports whether the driver says the database did not answer: a
// connection that failed, a send safe to retry or a timeout.
func (Ledger) NoAnswer(err error) bool {
	var conn *pgconn.ConnectError
	return errors.As(err, &conn) || pgconn.SafeToRetry(err) || pgconn.Timeout(err)
}

func (Ledger) OpenPluginApproval(ctx context.Context, db q, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error) {
	return guard.OpenPluginApproval(ctx, asPgx(db), d, s)
}

func (Ledger) ReadPluginApproval(ctx context.Context, db q, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	return guard.ReadPluginApproval(ctx, asPgx(db), id)
}

func (Ledger) ReadPluginApprovals(ctx context.Context, db q) ([]guardmodel.PluginApprovalRecord, error) {
	return guard.ReadPluginApprovals(ctx, asPgx(db))
}

func (Ledger) SubmitPluginApproval(ctx context.Context, db q, r guardmodel.PluginApprovalResponse) (time.Time, error) {
	return guard.SubmitPluginApproval(ctx, asPgx(db), r)
}

func (Ledger) PluginSettingsSHA256(ctx context.Context, db q, s guardmodel.PluginSettings) (string, error) {
	return guard.PluginSettingsSHA256(ctx, asPgx(db), s)
}

func (Ledger) RecordPluginEntryEvent(ctx context.Context, db q, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error {
	return guard.RecordPluginEntryEvent(ctx, asPgx(db), kind, d)
}

func (Ledger) RecordPluginTrustAdded(ctx context.Context, db q, keyID string) error {
	return guard.RecordPluginTrustAdded(ctx, asPgx(db), keyID)
}

func (Ledger) RecordPluginTrustRemoved(ctx context.Context, db q, keyID string) error {
	return guard.RecordPluginTrustRemoved(ctx, asPgx(db), keyID)
}

func (Ledger) ReadPluginRecords(ctx context.Context, db q) (guardmodel.PluginRecords, error) {
	return guard.ReadPluginRecords(ctx, asPgx(db))
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

func (s snapshot) PluginEntryEvents(ctx context.Context, name, instance string) ([]guardmodel.PluginEntryEvent, error) {
	return guard.PluginEntryEvents(ctx, s.tx, name, instance)
}

func (s snapshot) SeqRetired(ctx context.Context, seq int64) (bool, error) {
	return guard.SeqRetired(ctx, s.tx, seq)
}

func (s snapshot) ReadFeedRows(ctx context.Context, after int64, limit int, f guardmodel.FeedFilter) ([]guardmodel.FeedRow, error) {
	return guard.ReadFeedRows(ctx, s.tx, after, limit, f)
}

func (s snapshot) OldestSeqAfter(ctx context.Context, after int64) (int64, bool, error) {
	return guard.OldestSeqAfter(ctx, s.tx, after)
}
