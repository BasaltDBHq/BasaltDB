package guard

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The ledger kinds a feed/1 event is made from (guardmodel.Kind*).
const (
	KindChange          = guardmodel.KindChange
	KindRefused         = guardmodel.KindRefused
	KindApprovalPending = guardmodel.KindApprovalPending
	KindApproved        = guardmodel.KindApproved
	KindRevertPending   = guardmodel.KindRevertPending
	KindRevertSigned    = guardmodel.KindRevertSigned
	KindReverted        = guardmodel.KindReverted
	KindRevertRejected  = guardmodel.KindRevertRejected
)

// ledgerKind is the ledger's kind column.
const ledgerKind = "kind"

// FeedKinds are the ledger kinds feed/1 may carry. A CHANGE is an event only
// when its status is APPLIED, a REFUSED only when its op is not SELECT
// (ReadFeedRows filters both).
var FeedKinds = []string{
	KindChange, KindRefused, KindApprovalPending, KindApproved,
	KindRevertPending, KindRevertSigned, KindReverted, KindRevertRejected,
}

// FeedRow is one row of the calling agent's ledger that is a feed/1 event.
type FeedRow = guardmodel.FeedRow

// ReadFeedRows reads the calling agent's own ledger (agent_ledger shows only
// session_user's rows) after seq after: at most limit rows that are feed/1
// events, in seq order.
func ReadFeedRows(ctx context.Context, q Querier, after int64, limit int) ([]FeedRow, error) {
	if limit <= 0 {
		return nil, nil
	}
	sql, args, err := psql.Select("seq", "at", ledgerKind, "change_id", "op",
		"detail ->> 'runId'", "detail ->> 'taskId'", "detail ->> 'table'", "detail ->> 'rows'", "detail ->> 'cascadedRows'",
		"detail ->> 'approvalId'", "detail ->> 'expiresAt'", "detail ->> 'revertId'", "detail ->> 'code'").
		From("basalt_meta.agent_ledger").
		Where(sq.Gt{"seq": after}).
		Where(sq.Eq{ledgerKind: FeedKinds}).
		Where(sq.Expr("(kind <> ? OR detail ->> 'status' = 'APPLIED')", KindChange)).
		Where(sq.Expr("(kind <> ? OR op IS DISTINCT FROM 'SELECT')", KindRefused)).
		OrderBy("seq").Limit(uint64(limit)).ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (FeedRow, error) {
		var r FeedRow
		err := row.Scan(&r.Seq, &r.At, &r.Kind, &r.ChangeID, &r.Op,
			&r.RunID, &r.TaskID, &r.Table, &r.Rows, &r.CascadedRows,
			&r.ApprovalID, &r.ExpiresAt, &r.RevertID, &r.Code)
		return r, err
	})
}

// ChainHeadSeq is the seq of the ledger's last row (basalt_meta.chain_head),
// 0 for an empty ledger.
func ChainHeadSeq(ctx context.Context, q Querier) (int64, error) {
	sql, args, err := psql.Select("seq").From("basalt_meta.chain_head()").ToSql()
	if err != nil {
		return 0, err
	}
	var seq int64
	err = q.QueryRow(ctx, sql, args...).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// retiredProbe is a hash no ledger row has (a ledger hash is 32 bytes).
var retiredProbe = []byte{0}

// SeqRetired reports whether retention deleted ledger row seq: check_head
// answers true for a seq before the chain's anchor whatever hash it is
// given, and false for a row that remains (its hash differs from the probe)
// and for the anchor itself, the last row deleted, after which nothing is
// missing. seq 0 is the start of the chain: nothing before it was deleted.
func SeqRetired(ctx context.Context, q Querier, seq int64) (bool, error) {
	if seq <= 0 {
		return false, nil
	}
	return CheckHead(ctx, q, ChainHead{Seq: seq, Hash: retiredProbe})
}

// OldestSeqAfter is the seq of the calling agent's oldest ledger row after
// seq after, false when it has none.
func OldestSeqAfter(ctx context.Context, q Querier, after int64) (int64, bool, error) {
	sql, args, err := psql.Select("min(seq)").From("basalt_meta.agent_ledger").Where(sq.Gt{"seq": after}).ToSql()
	if err != nil {
		return 0, false, err
	}
	var seq *int64
	if err := q.QueryRow(ctx, sql, args...).Scan(&seq); err != nil {
		return 0, false, err
	}
	if seq == nil {
		return 0, false, nil
	}
	return *seq, true, nil
}

// ServedFrom is the seq of the newest record in the calling agent's ledger
// after seq after that begins serving entry (name, instance) to it: a
// PLUGIN_ENABLED, or a PLUGIN_CHANGED that adds an egress host or moves the
// endpoint (CONTRACT.md, Notifier messages, The cursor). False when there is
// none.
func ServedFrom(ctx context.Context, q Querier, name, instance string, after int64) (int64, bool, error) {
	sql, args, err := psql.Select("seq", ledgerKind, "detail -> 'egress'", "detail -> 'endpoint'").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{ledgerKind: []string{string(PluginEnabled), string(PluginChanged), string(PluginDisabled)}}).
		Where(sq.Expr("detail ->> 'name' = ?", name)).
		Where(sq.Expr("detail ->> 'instance' = ?", instance)).
		OrderBy("seq").ToSql()
	if err != nil {
		return 0, false, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return 0, false, err
	}
	type record struct {
		seq      int64
		kind     string
		egress   []byte
		endpoint []byte
	}
	recs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (record, error) {
		var r record
		err := row.Scan(&r.seq, &r.kind, &r.egress, &r.endpoint)
		return r, err
	})
	if err != nil {
		return 0, false, err
	}
	var from int64
	found := false
	for i, r := range recs {
		if r.seq <= after {
			continue
		}
		starts := r.kind == string(PluginEnabled)
		if r.kind == string(PluginChanged) && i > 0 {
			starts = widens(recs[i-1].egress, recs[i-1].endpoint, r.egress, r.endpoint)
		}
		if starts {
			from, found = r.seq, true
		}
	}
	return from, found, nil
}

// widens reports whether a plugin record's egress and endpoint, after the
// one before, add an egress host or move the endpoint. A detail that does
// not decode counts as a change: starting again at it only skips events.
func widens(prevEgress, prevEndpoint, egress, endpoint []byte) bool {
	var pe, e []string
	var pp, p PluginEndpoint
	if json.Unmarshal(prevEgress, &pe) != nil || json.Unmarshal(egress, &e) != nil ||
		json.Unmarshal(prevEndpoint, &pp) != nil || json.Unmarshal(endpoint, &p) != nil {
		return true
	}
	if pp != p {
		return true
	}
	return slices.ContainsFunc(e, func(h string) bool { return !slices.Contains(pe, h) })
}
