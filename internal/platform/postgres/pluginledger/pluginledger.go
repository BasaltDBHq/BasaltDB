// Package pluginledger is the guard's plugin records, approvals and feed
// reads as the plugin host's guard port (engine.Guard).
package pluginledger

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
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

// Ledger is engine.Guard: it forwards each call to the guard package, maps
// the database's answers to the plugin's typed ones (MapError,
// openApprovalError), and holds no state.
type Ledger struct{}

func (Ledger) AgentVersion(ctx context.Context, db q) (int, error) {
	v, err := guard.AgentVersion(ctx, asPgx(db))
	return v, MapError(err)
}

func (Ledger) AgentStatus(ctx context.Context, db q) (guardmodel.Status, error) {
	st, err := guard.AgentStatus(ctx, asPgx(db), guard.Migrations())
	return st, MapError(err)
}

func (Ledger) InstallID(ctx context.Context, db q) (uuid.UUID, error) {
	id, err := guard.InstallID(ctx, asPgx(db))
	return id, MapError(err)
}

func (Ledger) PluginApprovalsVersion() int { return guard.PluginApprovalsVersion }

// Kind is the store the agents' ledgers are in.
func (Ledger) Kind() action.StoreKind { return action.StorePostgres }

// NoAnswer reports whether the driver says the database did not answer: a
// connection that failed, a send safe to retry or a timeout.
func (Ledger) NoAnswer(err error) bool {
	var conn *pgconn.ConnectError
	return errors.As(err, &conn) || pgconn.SafeToRetry(err) || pgconn.Timeout(err)
}

func (Ledger) OpenPluginApproval(ctx context.Context, db q, d guardmodel.PluginApprovalDetail, s guardmodel.PluginSettings) (guardmodel.PluginApproval, error) {
	a, err := guard.OpenPluginApproval(ctx, asPgx(db), d, s)
	return a, openApprovalError(err)
}

func (Ledger) ReadPluginApprovals(ctx context.Context, db q) ([]guardmodel.PluginApprovalRecord, error) {
	r, err := guard.ReadPluginApprovals(ctx, asPgx(db))
	return r, MapError(err)
}

func (Ledger) PluginSettingsSHA256(ctx context.Context, db q, s guardmodel.PluginSettings) (string, error) {
	h, err := guard.PluginSettingsSHA256(ctx, asPgx(db), s)
	return h, MapError(err)
}

func (Ledger) RecordPluginEntryEvent(ctx context.Context, db q, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error {
	return MapError(guard.RecordPluginEntryEvent(ctx, asPgx(db), kind, d))
}

func (Ledger) RecordPluginTrustAdded(ctx context.Context, db q, keyID string) error {
	return MapError(guard.RecordPluginTrustAdded(ctx, asPgx(db), keyID))
}

func (Ledger) RecordPluginTrustRemoved(ctx context.Context, db q, keyID string) error {
	return MapError(guard.RecordPluginTrustRemoved(ctx, asPgx(db), keyID))
}

func (Ledger) ReadPluginRecords(ctx context.Context, db q) (guardmodel.PluginRecords, error) {
	r, err := guard.ReadPluginRecords(ctx, asPgx(db))
	return r, MapError(err)
}

// ReadSnapshot runs fn in one read-only repeatable-read transaction.
func (Ledger) ReadSnapshot(ctx context.Context, db q, fn func(guardmodel.FeedSnapshot) error) error {
	b, ok := db.(guard.TxBeginner)
	if !ok {
		return errors.New("the agent's connection cannot take a transaction")
	}
	return MapError(pgx.BeginTxFunc(ctx, b, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return fn(snapshot{tx: tx})
	}))
}

type snapshot struct{ tx pgx.Tx }

func (s snapshot) InstallID(ctx context.Context) (uuid.UUID, error) {
	id, err := guard.InstallID(ctx, s.tx)
	return id, MapError(err)
}

func (s snapshot) ChainHeadSeq(ctx context.Context) (int64, error) {
	seq, err := guard.ChainHeadSeq(ctx, s.tx)
	return seq, MapError(err)
}

func (s snapshot) PluginEntryEvents(ctx context.Context, name, instance string) ([]guardmodel.PluginEntryEvent, error) {
	ev, err := guard.PluginEntryEvents(ctx, s.tx, name, instance)
	return ev, MapError(err)
}

func (s snapshot) SeqRetired(ctx context.Context, seq int64) (bool, error) {
	retired, err := guard.SeqRetired(ctx, s.tx, seq)
	return retired, MapError(err)
}

func (s snapshot) ReadFeedRows(ctx context.Context, after int64, limit int, f guardmodel.FeedFilter) ([]guardmodel.FeedRow, error) {
	rows, err := guard.ReadFeedRows(ctx, s.tx, after, limit, f)
	return rows, MapError(err)
}

func (s snapshot) OldestSeqAfter(ctx context.Context, after int64) (int64, bool, error) {
	seq, ok, err := guard.OldestSeqAfter(ctx, s.tx, after)
	return seq, ok, MapError(err)
}
