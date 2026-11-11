package guard_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

var leads = []string{"public.leads"}

// newRun starts a run as the agent and returns its intent.
func newRun(t *testing.T, a *guardtest.Agent, text string) guard.Intent {
	t.Helper()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: text}
	require.NoError(t, guard.StartRun(context.Background(), a.Conn, in))
	return in
}

func requireCode(t *testing.T, err error, want guard.Code) {
	t.Helper()
	require.Error(t, err)
	got, ok := guard.CodeOf(err)
	require.True(t, ok, "not a guard error: %v", err)
	require.Equal(t, want, got, err.Error())
}

func count(t *testing.T, q guard.Querier, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, q.QueryRow(context.Background(), sql, args...).Scan(&n))
	return n
}

func TestWriteWithoutIntentRefused(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()

	_, err := a.Conn.Exec(ctx, `UPDATE public.leads SET status = 'merged' WHERE id = 4`)
	requireCode(t, err, guard.CodeIntentRequired)

	err = pgx.BeginFunc(ctx, a.Conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('basalt.intent', '', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE public.leads SET status = 'merged' WHERE id = 4`)
		return err
	})
	requireCode(t, err, guard.CodeIntentRequired)

	// People and the app are never blocked or recorded.
	d.Exec(t, `CREATE ROLE `+d.Names.Prefix+`_app LOGIN PASSWORD 'app'`)
	d.Exec(t, `GRANT ALL ON ALL TABLES IN SCHEMA public TO `+d.Names.Prefix+`_app`)
	appURL, err := guard.AgentConnString(d.URL, d.Names.Prefix+"_app", "app")
	require.NoError(t, err)
	app, err := pgdial.Connect(ctx, appURL)
	require.NoError(t, err)
	defer app.Close(ctx)
	_, err = app.Exec(ctx, `UPDATE public.leads SET score = score + 1`)
	require.NoError(t, err)
	_, err = app.Exec(ctx, `DELETE FROM public.leads WHERE id = 200`)
	require.NoError(t, err)
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger`))
}

func TestRecordsOldAndNewRows(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Merge duplicate case reports")

	var changeID uuid.UUID
	err := pgx.BeginFunc(ctx, a.Conn, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.leads SET status = $1 WHERE id = $2`, "merged", 4); err != nil {
			return err
		}
		var err error
		changeID, err = guard.FinishChange(ctx, tx, guard.Finish{
			Op: "UPDATE", Statement: "UPDATE public.leads SET status = $1 WHERE id = $2",
			Params: []any{"merged", 4}, Duration: 12 * time.Millisecond,
		})
		return err
	})
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), changeID.Version())

	var oldRow, newRow, key map[string]any
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT old_row, new_row, row_key FROM basalt_meta.ledger
		WHERE change_id = $1 AND kind = 'ROW_CHANGE'`, changeID).Scan(&oldRow, &newRow, &key))
	require.Equal(t, "open", oldRow["status"])
	require.Equal(t, "merged", newRow["status"])
	require.Equal(t, map[string]any{"id": float64(4)}, key)

	var (
		rows, durationMs  int
		status, statement string
		intent, agent     string
		runID             uuid.UUID
		params            []any
	)
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT rows, duration_ms, status, statement, intent, agent, run_id, params
		FROM basalt_meta.changes WHERE change_id = $1`, changeID).
		Scan(&rows, &durationMs, &status, &statement, &intent, &agent, &runID, &params))
	require.Equal(t, 1, rows)
	require.Equal(t, 12, durationMs)
	require.Equal(t, "APPLIED", status)
	require.Equal(t, "Merge duplicate case reports", intent)
	require.Equal(t, a.Role, agent)
	require.Equal(t, in.RunID, runID)
	require.Equal(t, []any{"merged", float64(4)}, params)

	var kinds []string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT array_agg(kind ORDER BY seq) FROM basalt_meta.ledger`).Scan(&kinds))
	require.Equal(t, []string{"RUN_STARTED", "ROW_CHANGE", "CHANGE"}, kinds)
}

func TestZeroRowWriteIsRecorded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "touch nothing")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 1 WHERE id = -1`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.changes WHERE rows = 0 AND status = 'APPLIED'`))
}

func TestIntentDoesNotLeakAcrossTransactions(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "first")

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 1 WHERE id = 1`))
	// Same connection, as a pooler would hand it to the next client.
	_, err := a.Conn.Exec(ctx, `UPDATE public.leads SET score = 2 WHERE id = 1`)
	requireCode(t, err, guard.CodeIntentRequired)
	var intent string
	require.NoError(t, a.Conn.QueryRow(ctx, `SELECT coalesce(current_setting('basalt.intent', true), '')`).Scan(&intent))
	require.Empty(t, intent)
}

func TestRunMustBelongToAgent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	b := d.NewAgent(t, "other", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "mine")

	err := guardtest.Guarded(ctx, b.Conn, in, `UPDATE public.leads SET score = 1 WHERE id = 1`)
	requireCode(t, err, guard.CodeNotAllowed)
	err = guard.StartRun(ctx, b.Conn, in)
	requireCode(t, err, guard.CodeLedgerInputInvalid)
}

func TestTruncateRefused(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE TABLE public.scratch (id int PRIMARY KEY)`)
	a := d.NewAgent(t, "bot", []string{"public.scratch"}, nil)
	d.Exec(t, `GRANT TRUNCATE ON public.scratch TO `+a.Role)
	_, err := a.Conn.Exec(context.Background(), `TRUNCATE public.scratch`)
	requireCode(t, err, guard.CodeNotAllowed)
}

func TestSuperuserNotGuarded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, nil)
	// The test admin is a superuser: a member of every role, skipped.
	d.Exec(t, `DELETE FROM public.leads WHERE id > 150`)
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger`))
}

func TestRecordRefusal(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "clean up")

	err := guardtest.Guarded(ctx, a.Conn, in, `DELETE FROM public.leads WHERE id = 1`)
	code, ok := guard.CodeOf(err)
	require.True(t, ok)
	id, err := guard.RecordRefusal(ctx, a.Conn, guard.Refusal{
		Intent: in, Op: "DELETE", Statement: "DELETE FROM public.leads WHERE id = 1",
		Code: string(code), Reason: err.Error(), Duration: time.Millisecond,
	})
	require.NoError(t, err)

	var status, gotCode string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT status, code FROM basalt_meta.changes WHERE change_id = $1`, id).
		Scan(&status, &gotCode))
	require.Equal(t, "REFUSED", status)
	require.Equal(t, "APPROVAL_REQUIRED", gotCode)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger WHERE kind = 'REFUSED' AND change_id = $1`, id))

	_, err = guard.RecordRefusal(ctx, a.Conn, guard.Refusal{Intent: in, Op: "DROP", Code: "X"})
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	_, err = guard.RecordRefusal(ctx, a.Conn, guard.Refusal{Intent: in, Op: "OTHER", Code: "lower"})
	requireCode(t, err, guard.CodeLedgerInputInvalid)
}

func TestHeartbeat(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	require.NoError(t, guard.Heartbeat(ctx, a.Conn, map[string]any{"engine": "test"}))
	var detail json.RawMessage
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT detail FROM basalt_meta.ledger WHERE kind = 'HEARTBEAT'`).Scan(&detail))
	require.JSONEq(t, `{"engine":"test","runId":null}`, string(detail))
}
