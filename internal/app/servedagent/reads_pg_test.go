package servedagent_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/core/action"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

func (h harness) startRun(t *testing.T, intent string) string {
	t.Helper()
	run, isError := h.call(t, "run_start", map[string]any{"intent": intent})
	require.False(t, isError, "%v", run)
	return str(t, run["runId"])
}

func (h harness) mustQuery(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	body, isError := h.query(t, args)
	require.False(t, isError, "%v", body)
	require.NotEmpty(t, str(t, body["changeId"]))
	return body
}

// readDetail is the READ ledger row of a read, as the admin sees it.
func readDetail(t *testing.T, d *guardtest.DB, changeID string) map[string]any {
	t.Helper()
	var detail map[string]any
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT detail FROM basalt_meta.ledger WHERE kind = 'READ' AND change_id = $1`, changeID).Scan(&detail))
	return detail
}

func xmin(t *testing.T, d *guardtest.DB, table string, id int) string {
	t.Helper()
	var v string
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT xmin::text FROM `+table+` WHERE id = $1`, id).Scan(&v))
	return v
}

// TestStaleWriteIsRefusedBeforeItLands is the competitor-test D4 scenario
// (the M1.5 gate): the agent reads a lead, a person changes it, the
// agent's update based on what it read is refused with STALE_READ, is
// recorded as a refusal, and never lands.
func TestStaleWriteIsRefusedBeforeItLands(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	runID := h.startRun(t, "Close leads nobody answered")

	read := h.mustQuery(t, map[string]any{"sql": "SELECT id, status FROM leads WHERE id = $1", "params": []any{42}, "runId": runID})
	before := xmin(t, d, "public.leads", 42)
	d.Exec(t, `UPDATE public.leads SET status = 'won' WHERE id = 42`) // a person, directly
	after := xmin(t, d, "public.leads", 42)

	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"lost", 42},
		"intent": "No answer for a week", "runId": runID,
	})
	requireToolError(t, body, isError, guidance.CodeStaleRead, "", "BS004")
	require.Contains(t, body["message"], `public.leads {"id": 42} read at xmin `+before+", now "+after)
	require.Equal(t, "won", leadStatus(t, d, 42), "the person's edit stands")

	recs := h.history(t, runID)
	require.Len(t, recs, 2)
	require.Equal(t, "REFUSED", recs[0]["status"])
	require.Equal(t, "UPDATE", recs[0]["op"])
	reason, ok := recs[0]["reason"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, guidance.CodeStaleRead, reason["code"])
	require.Equal(t, read["changeId"], recs[1]["changeId"])
	require.Equal(t, "READ", recs[1]["op"])

	// Read again, then the write is based on what the agent saw.
	h.mustQuery(t, map[string]any{"sql": "SELECT id, status FROM leads WHERE id = 42", "runId": runID})
	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = 0 WHERE id = 42", "intent": "Reset the score", "runId": runID,
	})
	require.False(t, isError, "%v", body)
}

func TestWriteRecordsWhatItWasBasedOn(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	runID := h.startRun(t, "Merge duplicates")
	read := h.mustQuery(t, map[string]any{"sql": "SELECT * FROM leads WHERE id = 4", "runId": runID})
	version := "xmin:" + xmin(t, d, "public.leads", 4)

	detail := readDetail(t, d, str(t, read["changeId"]))
	require.Equal(t, []any{map[string]any{"resource": "public.leads", "key": map[string]any{"id": float64(4)}, "version": version}},
		detail["versions"])
	require.Equal(t, []any{"public.leads"}, detail["resources"], "qualified as a write is")

	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'merged' WHERE id = 4", "intent": "Lead 4 duplicates lead 3", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	recs := h.history(t, runID)
	write := recs[0]
	want := map[string]any{"version": version, "changeId": read["changeId"]}
	require.Equal(t, want, write["basedOn"])
	rows, ok := write["rowChanges"].([]any)
	require.True(t, ok)
	row, ok := rows[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, want, row["basedOn"])
	require.NotContains(t, row, "blindWrite")

	// A write to a lead the run never read goes through, marked blind.
	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET score = 1 WHERE id = 5", "intent": "Bump lead 5", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	blind := h.history(t, runID)[0]
	require.NotContains(t, blind, "basedOn")
	rows, ok = blind["rowChanges"].([]any)
	require.True(t, ok)
	row, ok = rows[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, row["blindWrite"])
}

func TestJoinsAndAggregatesAreRecorded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", []string{"public.leads", "public.lead_notes"}, nil)
	h := newHarness(t, a.URL, action.DefaultLimits())
	runID := h.startRun(t, "Review notes")

	join := h.mustQuery(t, map[string]any{
		"sql":    "SELECT l.id, n.id AS note, n.note FROM leads l JOIN lead_notes n ON n.lead_id = l.id WHERE l.id = $1 ORDER BY n.id",
		"params": []any{1}, "runId": runID,
	})
	require.Equal(t, json.Number("2"), join["rowCount"])
	require.Len(t, join["columns"], 3, "version columns are stripped")
	row, ok := join["rows"].([]any)[0].(map[string]any)
	require.True(t, ok)
	require.Len(t, row, 3)
	detail := readDetail(t, d, str(t, join["changeId"]))
	require.Equal(t, []any{"public.lead_notes", "public.leads"}, detail["resources"])
	require.Len(t, detail["versions"], 4, "two rows, each with a lead and a note")

	agg := h.mustQuery(t, map[string]any{"sql": "SELECT count(id) AS n FROM lead_notes WHERE lead_id = 1", "runId": runID})
	detail = readDetail(t, d, str(t, agg["changeId"]))
	require.Equal(t, []any{"public.lead_notes"}, detail["resources"])
	require.Empty(t, detail["versions"], "an aggregate has no row identity; its statement and tables are recorded")
	require.InDelta(t, 1, detail["rows"], 0)

	// The join's versions guard the note too.
	d.Exec(t, `UPDATE public.lead_notes SET note = 'edited by a person' WHERE id = 2`)
	body, isError := h.call(t, "write", map[string]any{
		"sql": "UPDATE lead_notes SET note = 'seen' WHERE id = 2", "intent": "Mark the note seen", "runId": runID,
	})
	requireToolError(t, body, isError, guidance.CodeStaleRead, "", "BS004")
	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE lead_notes SET note = 'seen' WHERE id = 1", "intent": "Mark the note seen", "runId": runID,
	})
	require.False(t, isError, "%v", body)
}

func TestReadsOutsideARunAreRecorded(t *testing.T) {
	t.Parallel()
	d, h := guarded(t)
	body := h.mustQuery(t, map[string]any{"sql": "SELECT id FROM leads WHERE id <= 3"})
	var op, status string
	var rows int
	var run *string
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT op, status, rows, run_id::text FROM basalt_meta.changes WHERE change_id = $1`, str(t, body["changeId"])).
		Scan(&op, &status, &rows, &run))
	require.Equal(t, []any{"READ", "APPLIED", 3}, []any{op, status, rows})
	require.Nil(t, run)
	require.Len(t, readDetail(t, d, str(t, body["changeId"]))["versions"], 3)
}

// TestStaleChecksSurviveAPooledConnection runs two runs interleaved on a
// one-connection pool: nothing about a run lives in the session, so each
// write is checked against its own run's reads only.
func TestStaleChecksSurviveAPooledConnection(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	h := newHarnessConns(t, a.URL, action.DefaultLimits(), 1)
	first := h.startRun(t, "First run")
	second := h.startRun(t, "Second run")
	write := func(runID string, id int) (map[string]any, bool) {
		return h.call(t, "write", map[string]any{
			"sql": "UPDATE leads SET score = score + 1 WHERE id = $1", "params": []any{id},
			"intent": "Bump", "runId": runID,
		})
	}

	h.mustQuery(t, map[string]any{"sql": "SELECT * FROM leads WHERE id = 10", "runId": first})
	h.mustQuery(t, map[string]any{"sql": "SELECT * FROM leads WHERE id = 11", "runId": second})

	body, isError := write(second, 10)
	require.False(t, isError, "the second run never read lead 10: a blind write, %v", body)
	body, isError = write(first, 11)
	require.False(t, isError, "the first run never read lead 11: a blind write, %v", body)

	body, isError = write(first, 10)
	requireToolError(t, body, isError, guidance.CodeStaleRead, "", "BS004")
	body, isError = write(second, 11)
	requireToolError(t, body, isError, guidance.CodeStaleRead, "", "BS004")

	// The runs' own writes are what they know now.
	body, isError = write(second, 10)
	require.False(t, isError, "%v", body)
	body, isError = write(first, 11)
	require.False(t, isError, "%v", body)
}
