package guard

import (
	"context"
	"encoding/json"
	"fmt"

	sq "github.com/Masterminds/squirrel"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// pluginTrustDetail is PLUGIN_TRUST_ADDED's detail.
type pluginTrustDetail struct {
	SignerKeyID string `json:"signerKeyId"`
}

// RecordPluginEntryEvent appends a plugin entry event to the calling
// agent's own ledger. The guard refuses a detail outside the schema with
// LEDGER_INPUT_INVALID (BS008).
func RecordPluginEntryEvent(ctx context.Context, q Querier, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error {
	if kind == guardmodel.PluginTrustAdded || kind == guardmodel.PluginTrustRemoved {
		return fmt.Errorf("guard: %s carries a key id, not an entry", kind)
	}
	if d.Egress == nil {
		d.Egress = []string{}
	}
	return recordPluginEvent(ctx, q, kind, d)
}

// RecordPluginTrustAdded appends PLUGIN_TRUST_ADDED for keyID to the
// calling agent's own ledger.
func RecordPluginTrustAdded(ctx context.Context, q Querier, keyID string) error {
	return recordPluginEvent(ctx, q, guardmodel.PluginTrustAdded, pluginTrustDetail{SignerKeyID: keyID})
}

// RecordPluginTrustRemoved records that keyID is no longer trusted. It
// needs schema version 4; an older guard refuses the kind (BS008).
func RecordPluginTrustRemoved(ctx context.Context, q Querier, keyID string) error {
	return recordPluginEvent(ctx, q, guardmodel.PluginTrustRemoved, pluginTrustDetail{SignerKeyID: keyID})
}

func recordPluginEvent(ctx context.Context, q Querier, kind guardmodel.PluginEventKind, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return execCall(ctx, q, sq.Expr("basalt_meta.record_plugin_event(?, ?::jsonb)", string(kind), string(b)))
}

// ReadPluginRecords reads the calling agent's plugin events from its own
// ledger (agent_ledger shows only session_user's rows). A row the agent
// could not have written through record_plugin_event cannot be there, but
// a detail that does not decode is skipped rather than trusted.
func ReadPluginRecords(ctx context.Context, q Querier) (guardmodel.PluginRecords, error) {
	var out guardmodel.PluginRecords
	sql, args, err := psql.Select("kind", "detail").
		Options("DISTINCT ON (detail->>'name', detail->>'instance')").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": []string{string(guardmodel.PluginEnabled), string(guardmodel.PluginDisabled), string(guardmodel.PluginChanged)}}).
		OrderBy("detail->>'name'", "detail->>'instance'", "seq DESC").ToSql()
	if err != nil {
		return out, err
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var raw []byte
		if err := rows.Scan(&kind, &raw); err != nil {
			return out, err
		}
		var d guardmodel.PluginDetail
		if json.Unmarshal(raw, &d) != nil || d.Name == "" || d.Instance == "" {
			continue // not a detail record_plugin_event accepts
		}
		out.Entries = append(out.Entries, guardmodel.PluginRecord{Kind: guardmodel.PluginEventKind(kind), Detail: d})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// Each key's latest PLUGIN_TRUST_ADDED or PLUGIN_TRUST_REMOVED.
	sql, args, err = psql.Select("kind", "detail->>'signerKeyId'").
		Options("DISTINCT ON (detail->>'signerKeyId')").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": []string{string(guardmodel.PluginTrustAdded), string(guardmodel.PluginTrustRemoved)}}).
		OrderBy("detail->>'signerKeyId'", "seq DESC").ToSql()
	if err != nil {
		return out, err
	}
	keys, err := q.Query(ctx, sql, args...)
	if err != nil {
		return out, err
	}
	defer keys.Close()
	for keys.Next() {
		var kind string
		var k *string
		if err := keys.Scan(&kind, &k); err != nil {
			return out, err
		}
		if k != nil {
			out.LatestTrustEvents = append(out.LatestTrustEvents, guardmodel.PluginTrustEvent{KeyID: *k, Kind: guardmodel.PluginEventKind(kind)})
		}
	}
	return out, keys.Err()
}
