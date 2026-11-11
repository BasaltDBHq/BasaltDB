package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

func line(action, op, table, key string) revert.Line {
	l := revert.Line{Action: action, Op: op, Table: table, Key: json.RawMessage(key)}
	if action == revert.ActionSkip {
		conflict := "CHANGED_AFTER"
		l.Conflict = &conflict
	}
	return l
}

func keysIn(lines []revert.Line) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.Table+string(l.Key)+l.RowHash)
	}
	return out
}

func TestDisplayOrder(t *testing.T) {
	t.Parallel()
	const restore, skip = revert.ActionRestore, revert.ActionSkip
	in := []revert.Line{
		line(skip, "UPDATE", "public.leads", `{"id": 2}`),
		line(restore, "UPDATE", "public.leads", `{"id": 10}`),
		line(restore, "UPDATE", "public.leads", `{"id": 1}`),
		line(restore, "DELETE", "public.leads", `{"id": 7}`),
		line(restore, "UPDATE", "public.leads", `{"id": 3}`),
		line(restore, "INSERT", "public.notes", `{"id": 20}`),
		line(restore, "INSERT", "public.leads", `{"id": 4}`),
		line(restore, "UPDATE", "public.leads", `{"id": 5}`),
		{Action: restore, Op: "UPDATE", Table: "public.leads", Redacted: true, RowHash: "aa"},
		line(restore, "UPDATE", "public.a", `{"id": 99}`),
	}
	got := keysIn(displayOrder(in))
	require.Equal(t, []string{
		`public.leads{"id": 4}`, `public.notes{"id": 20}`, // re-inserts first
		`public.a{"id": 99}`, `public.leads{"id": 1}`, `public.leads{"id": 3}`, `public.leads{"id": 5}`, `public.leads{"id": 10}`, "public.leadsaa",
		`public.leads{"id": 7}`, // deletes
		`public.leads{"id": 2}`, // skipped last
	}, got)
	require.Equal(t, `public.leads{"id": 2}`, keysIn(in)[0], "the signed order is left alone")
}

func TestCompareKeys(t *testing.T) {
	t.Parallel()
	less := [][2]string{
		{`{"id": 2}`, `{"id": 10}`},
		{`{"id": -1}`, `{"id": 0.5}`},
		{`{"id": 99999999999999999998}`, `{"id": 99999999999999999999}`},
		{`{"code": "lead-2"}`, `{"code": "lead-10"}`},
		{`{"code": "a9"}`, `{"code": "b1"}`},
		{`{"org": 1, "id": 10}`, `{"org": 2, "id": 1}`},
		{`{"org": 1, "id": 2}`, `{"org": 1, "id": 10}`},
	}
	for _, p := range less {
		require.Negative(t, compareKeys(json.RawMessage(p[0]), json.RawMessage(p[1])), "%s < %s", p[0], p[1])
		require.Positive(t, compareKeys(json.RawMessage(p[1]), json.RawMessage(p[0])), "%s > %s", p[1], p[0])
	}
	require.Zero(t, compareKeys(json.RawMessage(`{"id": 1}`), json.RawMessage(`{"id": 1}`)))
	require.Negative(t, naturalCompare("x1", "x01"), "equal values: the shorter spelling first")
	require.Negative(t, naturalCompare("x01", "x2"))
}

func TestCompactRows(t *testing.T) {
	t.Parallel()
	r := ledger.RowChange{
		Op: "UPDATE", Table: "public.leads", Key: map[string]any{"id": float64(4)},
		Before:  map[string]any{"id": float64(4), "status": "NEW", "score": float64(1), "note": "a b"},
		After:   map[string]any{"id": float64(4), "status": "CONTACTED", "score": float64(1), "note": nil},
		BasedOn: &ledger.BasedOn{Version: "xmin:7"},
	}
	require.Equal(t, `UPDATE public.leads (read at xmin:7) {"id":4} note "a b" -> null, status NEW -> CONTACTED`, rowLine(r, false))
	require.Contains(t, rowLine(r, true), `before={"id":4,"note":"a b","score":1,"status":"NEW"}`)

	del := ledger.RowChange{Op: "DELETE", Table: "public.notes", Key: map[string]any{"id": float64(5)}, Cascaded: true,
		Before: map[string]any{"id": float64(5), "body": "x"}}
	require.Equal(t, `DELETE public.notes (cascaded) {"id":5}`, rowLine(del, false))
	require.Equal(t, `"true"`, displayValue("true"))
	require.Equal(t, `"12"`, displayValue("12"))
}

func TestLogGroupsReads(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 11, 6, 2, 11, 0, time.UTC)
	ms := 3
	read := func(table string, rows int) ledger.Change {
		return ledger.Change{ID: uuid.Must(uuid.NewV7()), At: at, Op: "SELECT", Status: "APPLIED", Table: table, Rows: rows, DurationMs: &ms}
	}
	write := ledger.Change{ID: uuid.Must(uuid.NewV7()), At: at, Op: "UPDATE", Status: "APPLIED", Table: "public.leads", Rows: 1, Intent: "fix"}
	changes := []ledger.Change{read("public.leads", 10), read("public.notes", 2), read("public.leads", 30), write, read("public.leads", 1)}

	var out bytes.Buffer
	c := &cliIO{ctx: context.Background(), stdout: &out}
	printText(c, changes, nil, false)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3)
	require.Equal(t, "2026-11-11T06:02:11Z  APPLIED  SELECT 3 reads, 42 rows: public.leads (2), public.notes (1)", lines[0])
	require.Contains(t, lines[1], "UPDATE public.leads")
	require.Contains(t, lines[2], "SELECT public.leads", "a single read keeps its own line")

	out.Reset()
	printText(c, changes, nil, true)
	require.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), 5, "--full lists every read")
}
