package guard

import (
	"context"
	"encoding/json"
	"fmt"

	sq "github.com/Masterminds/squirrel"
)

// pluginTrustDetail is PLUGIN_TRUST_ADDED's detail.
type pluginTrustDetail struct {
	SignerKeyID string `json:"signerKeyId"`
}

// RecordPluginEntryEvent appends a plugin entry event to the calling
// agent's own ledger. The guard refuses a detail outside the schema with
// LEDGER_INPUT_INVALID (BS008).
func RecordPluginEntryEvent(ctx context.Context, q Querier, kind PluginEventKind, d PluginDetail) error {
	if kind == PluginTrustAdded || kind == PluginTrustRemoved {
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
	return recordPluginEvent(ctx, q, PluginTrustAdded, pluginTrustDetail{SignerKeyID: keyID})
}

// RecordPluginTrustRemoved records that keyID is no longer trusted. It
// needs schema version 4; an older guard refuses the kind (BS008).
func RecordPluginTrustRemoved(ctx context.Context, q Querier, keyID string) error {
	return recordPluginEvent(ctx, q, PluginTrustRemoved, pluginTrustDetail{SignerKeyID: keyID})
}

func recordPluginEvent(ctx context.Context, q Querier, kind PluginEventKind, detail any) error {
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
func ReadPluginRecords(ctx context.Context, q Querier) (PluginRecords, error) {
	var out PluginRecords
	sql, args, err := psql.Select("kind", "detail").
		Options("DISTINCT ON (detail->>'name', detail->>'instance')").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": []string{string(PluginEnabled), string(PluginDisabled), string(PluginChanged)}}).
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
		var d PluginDetail
		if json.Unmarshal(raw, &d) != nil || d.Name == "" || d.Instance == "" {
			continue // not a detail record_plugin_event accepts
		}
		out.Entries = append(out.Entries, PluginRecord{Kind: PluginEventKind(kind), Detail: d})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// A key is trusted on the record when its latest PLUGIN_TRUST_ADDED or
	// PLUGIN_TRUST_REMOVED is an ADDED.
	sql, args, err = psql.Select("kind", "detail->>'signerKeyId'").
		Options("DISTINCT ON (detail->>'signerKeyId')").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": []string{string(PluginTrustAdded), string(PluginTrustRemoved)}}).
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
		if k != nil && kind == string(PluginTrustAdded) {
			out.TrustKeys = append(out.TrustKeys, *k)
		}
	}
	return out, keys.Err()
}

// OwedPluginEnd is the PLUGIN_DISABLED the calling agent owes for the entry
// (name, instance), false when it owes none: its ledger records the entry as
// served (the detail last recorded), or its newest plugin approval naming
// it is signed and not ended (the detail that approval binds). Writing it
// ends the approval for that agent (CONTRACT.md, Plugin approval, Turning
// off ends it). It needs schema version PluginApprovalsVersion.
func OwedPluginEnd(ctx context.Context, q Querier, name, instance string) (PluginDetail, bool, error) {
	recs, err := ReadPluginRecords(ctx, q)
	if err != nil {
		return PluginDetail{}, false, err
	}
	for _, r := range recs.Entries {
		if r.Detail.Name == name && r.Detail.Instance == instance && r.Enabled() {
			return r.Detail, true, nil
		}
	}
	apps, err := ReadPluginApprovals(ctx, q)
	if err != nil {
		return PluginDetail{}, false, err
	}
	for _, a := range apps {
		if a.Name != name || a.Instance != instance || !a.NamesCaller {
			continue
		}
		if a.Status != PluginApprovalStatusApproved || a.ApprovedAt == nil || a.Ended() {
			return PluginDetail{}, false, nil
		}
		b := a.Bound
		return PluginDetail{
			Name: b.Name, Instance: b.Instance, Version: b.Version, ManifestSHA256: b.ManifestSHA256,
			Hooks: b.Hooks, Roles: b.Roles, Egress: b.Egress, Endpoint: b.Endpoint, Isolation: b.Isolation,
			Signer: b.Signer, SignerKeyID: b.SignerKeyID,
		}, true, nil
	}
	return PluginDetail{}, false, nil
}

// EndPluginApproval writes the PLUGIN_DISABLED the calling agent owes for
// (name, instance), if any (OwedPluginEnd). One implementation for the
// engine and the basalt plugin commands.
func EndPluginApproval(ctx context.Context, q Querier, name, instance string) error {
	d, owed, err := OwedPluginEnd(ctx, q, name, instance)
	if err != nil || !owed {
		return err
	}
	return RecordPluginEntryEvent(ctx, q, PluginDisabled, d)
}
