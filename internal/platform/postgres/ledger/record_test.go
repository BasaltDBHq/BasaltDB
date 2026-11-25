package ledger_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/testkit/toolschema"
)

// Row values in a change record are RFC 3339 UTC: the jsonb the guard stored
// carries the session zone of the write (CONTRACT.md, Wire format).
func TestRecordFromDomainTimestampsAreUTC(t *testing.T) {
	t.Parallel()
	rec := ledger.RecordFromDomain(action.Change{ID: uuid.Must(uuid.NewV7())}, []action.RowChange{{
		Table: "public.leads", Op: "UPDATE",
		Key:    map[string]any{"id": 1.0, "seen": "2026-11-12T14:08:04+02:00"},
		Before: map[string]any{"updated_at": "2026-11-12T14:08:04.513958+02:00", "note": "plain", "local": "2026-11-12T14:08:04"},
		After:  map[string]any{"updated_at": "2026-11-12T14:11:27+02:00", "tags": []any{"2026-11-12T00:00:00-05:00"}},
	}})
	row := rec.RowChanges[0]
	require.Equal(t, map[string]any{"id": 1.0, "seen": "2026-11-12T12:08:04Z"}, row.Key)
	require.Equal(t, map[string]any{"updated_at": "2026-11-12T12:08:04.513958Z", "note": "plain", "local": "2026-11-12T14:08:04"}, row.Before)
	require.Equal(t, map[string]any{"updated_at": "2026-11-12T12:11:27Z", "tags": []any{"2026-11-12T05:00:00Z"}}, row.After)
}

// A change record in each form run_history serves validates against the
// tool's closed outputSchema: a read, a write with its rows, a refusal with
// no verb (OTHER), and an action that named no resource.
func TestRecordMatchesRunHistorySchema(t *testing.T) {
	t.Parallel()
	sch := toolschema.Output(t, "run_history")
	run := uuid.NullUUID{UUID: uuid.Must(uuid.NewV7()), Valid: true}
	at := time.Date(2026, 11, 25, 6, 2, 11, 0, time.UTC)
	ms := 3
	read := action.Change{
		ID: uuid.Must(uuid.NewV7()), At: at, Agent: "basalt_agent_bot", RunID: run, Intent: "Read leads",
		Op: "READ", Verb: "SELECT", Table: "leads", Statement: "SELECT id FROM leads", Params: json.RawMessage(`[]`),
		Rows: 2, DurationMs: &ms, Status: "APPLIED",
	}
	write := action.Change{
		ID: uuid.Must(uuid.NewV7()), At: at, Agent: "basalt_agent_bot", RunID: run, Intent: "Merge lead 4",
		Op: "UPDATE", Verb: "INSERT", Table: "public.leads", Statement: "INSERT INTO leads (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET id = excluded.id",
		Params: json.RawMessage(`[4]`), Rows: 1, Status: "APPLIED",
	}
	refused := action.Change{
		ID: uuid.Must(uuid.NewV7()), At: at, Agent: "basalt_agent_bot", RunID: run, Op: "OTHER",
		Statement: "DROP TABLE leads", Status: "REFUSED", Code: "STATEMENT_REFUSED", Reason: "DDL_NOT_ALLOWED",
	}
	rows := []action.RowChange{{Table: "public.leads", Op: "UPDATE", Key: map[string]any{"id": 4.0}, After: map[string]any{"id": 4.0}}}
	records := []ledger.Record{
		ledger.RecordFromDomain(read, nil),
		ledger.RecordFromDomain(write, rows),
		ledger.RecordFromDomain(refused, nil),
	}
	toolschema.Validate(t, sch, map[string]any{"items": records})

	require.Equal(t, ledger.RecordStore{Kind: "POSTGRES", Verb: "SELECT"}, records[0].Store)
	require.Equal(t, "INSERT", records[1].Store.Verb, "the request's own command, not the op")
	require.Equal(t, "public.leads", records[1].Resource)
	require.Equal(t, "RECORD", records[1].Shape)
	require.Equal(t, "RECORD", records[1].RowChanges[0].Shape)
	require.Equal(t, ledger.RecordStore{Kind: "POSTGRES"}, records[2].Store, "OTHER with no command has no verb")
	require.Empty(t, records[2].Resource)
	require.Empty(t, records[2].Shape, "no shape without a resource")
	require.Equal(t, &ledger.RecordRequest{Kind: "SQL", Statement: "DROP TABLE leads"}, records[2].Request)

	raw, err := json.Marshal(records[1])
	require.NoError(t, err)
	var old map[string]any
	require.NoError(t, json.Unmarshal(raw, &old))
	old["target"] = map[string]any{"table": "public.leads"}
	toolschema.Refuses(t, sch, map[string]any{"items": []any{old}})
}
