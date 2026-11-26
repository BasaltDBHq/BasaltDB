package guard

import (
	"context"
	"encoding/json"
	"errors"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// ledgerKind is the ledger's kind column.
const ledgerKind = "kind"

// ReadFeedRows reads the calling agent's own ledger (agent_ledger shows only
// session_user's rows) after seq after: at most limit rows that f keeps, in
// seq order.
func ReadFeedRows(ctx context.Context, q Querier, after int64, limit int, f guardmodel.FeedFilter) ([]guardmodel.FeedRow, error) {
	if limit <= 0 {
		return nil, nil
	}
	b := sqlport.Builder.Select("seq", "at", ledgerKind, "change_id", "op", "verb",
		"detail ->> 'runId'", "detail ->> 'taskId'", "detail ->> 'resource'", "detail ->> 'rows'", "detail ->> 'cascadedRows'",
		"detail ->> 'approvalId'", "detail ->> 'expiresAt'", "detail ->> 'revertId'", "detail ->> 'code'").
		From("basalt_meta.agent_ledger").
		Where(sq.Gt{"seq": after}).
		Where(sq.Eq{ledgerKind: f.Kinds})
	if !f.IncludeUnappliedChanges {
		b = b.Where(sq.Expr("(kind <> ? OR detail ->> 'status' = 'APPLIED')", guardmodel.KindChange))
	}
	if !f.IncludeRefusedReads {
		b = b.Where(sq.Expr("(kind <> ? OR op IS DISTINCT FROM 'READ')", guardmodel.KindRefused))
	}
	sql, args, err := b.OrderBy("seq").Limit(uint64(limit)).ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (guardmodel.FeedRow, error) {
		var r guardmodel.FeedRow
		err := row.Scan(&r.Seq, &r.At, &r.Kind, &r.ChangeID, &r.Op, &r.Verb,
			&r.RunID, &r.TaskID, &r.Table, &r.Rows, &r.CascadedRows,
			&r.ApprovalID, &r.ExpiresAt, &r.RevertID, &r.Code)
		return r, err
	})
}

// ChainHeadSeq is the seq of the ledger's last row (basalt_meta.chain_head),
// 0 for an empty ledger.
func ChainHeadSeq(ctx context.Context, q Querier) (int64, error) {
	sql, args, err := sqlport.Builder.Select("seq").From("basalt_meta.chain_head()").ToSql()
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
	sql, args, err := sqlport.Builder.Select("min(seq)").From("basalt_meta.agent_ledger").Where(sq.Gt{"seq": after}).ToSql()
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

// PluginEntryEvents are the PLUGIN_ENABLED, PLUGIN_CHANGED and
// PLUGIN_DISABLED records of entry (name, instance) in the calling agent's
// ledger, in seq order, with their egress and endpoint decoded; a record
// whose egress or endpoint does not decode has DecodeErr set.
func PluginEntryEvents(ctx context.Context, q Querier, name, instance string) ([]guardmodel.PluginEntryEvent, error) {
	sql, args, err := sqlport.Builder.Select("seq", ledgerKind, "detail -> 'egress'", "detail -> 'endpoint'").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{ledgerKind: []string{string(guardmodel.PluginEnabled), string(guardmodel.PluginChanged), string(guardmodel.PluginDisabled)}}).
		Where(sq.Expr("detail ->> 'name' = ?", name)).
		Where(sq.Expr("detail ->> 'instance' = ?", instance)).
		OrderBy("seq").ToSql()
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (guardmodel.PluginEntryEvent, error) {
		var (
			e                guardmodel.PluginEntryEvent
			egress, endpoint []byte
		)
		if err := row.Scan(&e.Seq, &e.Kind, &egress, &endpoint); err != nil {
			return e, err
		}
		e.DecodeErr = !decodes(egress, &e.Egress) || !decodes(endpoint, &e.Endpoint)
		return e, nil
	})
}

// decodes reports whether raw decodes as JSON into v.
func decodes(raw []byte, v any) bool { return json.Unmarshal(raw, v) == nil }
