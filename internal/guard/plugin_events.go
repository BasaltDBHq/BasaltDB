package guard

import (
	"context"
	"encoding/json"
	"fmt"

	sq "github.com/Masterminds/squirrel"
)

// PluginEventKind is a plugin ledger event (CONTRACT.md, Plugins, In the
// ledger).
type PluginEventKind string

// Plugin ledger events, written with record_plugin_event (version 3).
const (
	PluginEnabled    PluginEventKind = "PLUGIN_ENABLED"
	PluginDisabled   PluginEventKind = "PLUGIN_DISABLED"
	PluginChanged    PluginEventKind = "PLUGIN_CHANGED"
	PluginTrustAdded PluginEventKind = "PLUGIN_TRUST_ADDED"
)

// Endpoint kinds and isolation values of a plugin event's detail.
const (
	PluginEndpointLocal  = "LOCAL"
	PluginEndpointRemote = "REMOTE"

	PluginFilesOSUser = "OS_USER"
	PluginFilesNone   = "NONE"

	PluginNetworkEnforced    = "ENFORCED"
	PluginNetworkDeclared    = "DECLARED"
	PluginNetworkNotEnforced = "NOT_ENFORCED"
)

// PluginDetail is the detail of a plugin entry event (PLUGIN_ENABLED,
// PLUGIN_DISABLED, PLUGIN_CHANGED), api/plugin/events.schema.json. It
// holds no config value and names no agent.
type PluginDetail struct {
	Name           string   `json:"name"`
	Instance       string   `json:"instance"`
	Version        string   `json:"version"`
	ManifestSHA256 string   `json:"manifestSha256"`
	SignerKeyID    string   `json:"signerKeyId"`
	Hooks          []string `json:"hooks"`
	// Roles are wire.detect's declared roles; omitted otherwise.
	Roles []string `json:"roles,omitempty"`
	// Egress is never nil: the guard wants an array, empty for none.
	Egress    []string         `json:"egress"`
	Endpoint  PluginEndpoint   `json:"endpoint"`
	Isolation *PluginIsolation `json:"isolation,omitempty"`
	Model     *PluginModel     `json:"model,omitempty"`
}

// PluginEndpoint is where an entry runs: LOCAL, or REMOTE with the host:port.
type PluginEndpoint struct {
	Kind string `json:"kind"`
	Host string `json:"host,omitempty"`
}

// PluginIsolation is a local entry's isolation.
type PluginIsolation struct {
	Files   string `json:"files"`
	Network string `json:"network"`
}

// PluginModel is the model a plugin reports.
type PluginModel struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// pluginTrustDetail is PLUGIN_TRUST_ADDED's detail.
type pluginTrustDetail struct {
	SignerKeyID string `json:"signerKeyId"`
}

// RecordPluginEntryEvent appends a plugin entry event to the calling
// agent's own ledger. The guard refuses a detail outside the schema with
// LEDGER_INPUT_INVALID (BS008).
func RecordPluginEntryEvent(ctx context.Context, q Querier, kind PluginEventKind, d PluginDetail) error {
	if kind == PluginTrustAdded {
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

func recordPluginEvent(ctx context.Context, q Querier, kind PluginEventKind, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return execCall(ctx, q, sq.Expr("basalt_meta.record_plugin_event(?, ?::jsonb)", string(kind), string(b)))
}

// PluginRecord is the latest plugin entry event of one (name, instance) in
// an agent's ledger.
type PluginRecord struct {
	Kind   PluginEventKind
	Detail PluginDetail
}

// Enabled reports whether the record leaves the entry served: its latest
// event is PLUGIN_ENABLED or PLUGIN_CHANGED.
func (r PluginRecord) Enabled() bool { return r.Kind != PluginDisabled }

// PluginRecords is what an agent's ledger says of its plugins: the latest
// event of each entry, in name and instance order, and the trust keys
// recorded as added.
type PluginRecords struct {
	Entries   []PluginRecord
	TrustKeys []string
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
	sql, args, err = psql.Select("DISTINCT detail->>'signerKeyId'").
		From("basalt_meta.agent_ledger").
		Where(sq.Eq{"kind": string(PluginTrustAdded)}).
		OrderBy("1").ToSql()
	if err != nil {
		return out, err
	}
	keys, err := q.Query(ctx, sql, args...)
	if err != nil {
		return out, err
	}
	defer keys.Close()
	for keys.Next() {
		var k *string
		if err := keys.Scan(&k); err != nil {
			return out, err
		}
		if k != nil {
			out.TrustKeys = append(out.TrustKeys, *k)
		}
	}
	return out, keys.Err()
}

// EnabledPlugins are the entries the records leave served, in name and
// instance order.
func (r PluginRecords) EnabledPlugins() []PluginDetail {
	var out []PluginDetail
	for _, e := range r.Entries {
		if e.Enabled() {
			out = append(out, e.Detail)
		}
	}
	return out
}
