package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// withVars runs stmt in a transaction with intent plus extra session
// variables set transaction-local, and commits.
func withVars(ctx context.Context, c *pgx.Conn, in guard.Intent, vars map[string]string, stmt string) error {
	return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in, guardtest.Timeout); err != nil {
			return err
		}
		for k, v := range vars {
			if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, k, v); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, stmt)
		return err
	})
}

var preview = map[string]string{"basalt.mode": guard.ModePreview}

func TestRowLimits(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "policy")

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 1 WHERE id BETWEEN 101 AND 110`))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
		`INSERT INTO public.leads SELECT g, 'new ' || g FROM generate_series(1001, 1010) g`))

	cases := []struct {
		name string
		vars map[string]string
		stmt string
		want guard.Code
	}{
		{"update 11 held", nil, `UPDATE public.leads SET score = 2 WHERE id BETWEEN 101 AND 111`, guard.CodeApprovalRequired},
		{"update 51 held at row 11", nil, `UPDATE public.leads SET score = 2 WHERE id BETWEEN 101 AND 151`, guard.CodeApprovalRequired},
		{"insert 11 held", nil, `INSERT INTO public.leads SELECT g, 'n' FROM generate_series(2001, 2011) g`, guard.CodeApprovalRequired},
		{"delete 1 held", nil, `DELETE FROM public.leads WHERE id = 150`, guard.CodeApprovalRequired},
		{"preview 51 refused", preview, `UPDATE public.leads SET score = 2 WHERE id BETWEEN 101 AND 151`, guard.CodeRowLimitExceeded},
		{"preview never commits", preview, `UPDATE public.leads SET score = 3 WHERE id = 101`, guard.CodePreviewCannotCommit},
		{
			"unknown approval",
			map[string]string{"basalt.approval_id": "0193a4c2-0000-7000-8000-000000000000"},
			`UPDATE public.leads SET score = 3 WHERE id = 101`, guard.CodeApprovalInvalid,
		},
		{"unknown mode", map[string]string{"basalt.mode": "OFF"}, `UPDATE public.leads SET score = 3 WHERE id = 101`, guard.CodeNotAllowed},
		{"bad run id", map[string]string{"basalt.run_id": "run_7f3k"}, `UPDATE public.leads SET score = 3 WHERE id = 101`, guard.CodeLedgerInputInvalid},
	}
	for _, tc := range cases {
		err := withVars(ctx, a.Conn, in, tc.vars, tc.stmt)
		require.Error(t, err, tc.name)
		got, ok := guard.CodeOf(err)
		require.True(t, ok, "%s: %v", tc.name, err)
		require.Equal(t, tc.want, got, "%s: %v", tc.name, err)
	}

	// Moving the commit check earlier fails closed on a preview too.
	err := withVars(ctx, a.Conn, in, preview, `SET CONSTRAINTS ALL IMMEDIATE; UPDATE public.leads SET score = 3 WHERE id = 101`)
	requireCode(t, err, guard.CodePreviewCannotCommit)

	// A loop of small writes is not blocked.
	for i := 0; i < 12; i++ {
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = score + 1 WHERE id = 120`))
	}
	var score int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT score FROM public.leads WHERE id = 120`).Scan(&score))
	require.Equal(t, 120%7+12, score)
}

func TestUpsertCountedOnce(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "upsert")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
		`INSERT INTO public.leads (id, name) VALUES (5, 'five') ON CONFLICT (id) DO UPDATE SET name = excluded.name`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT rows FROM basalt_meta.changes WHERE status = 'APPLIED'`))
}

// previewRows runs stmt in PREVIEW mode as the agent and returns the
// cascaded flag per (table, op) from the ledger, before rolling back.
func previewRows(t *testing.T, a *guardtest.Agent, in guard.Intent, stmt string) (map[string]int, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := a.Conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	require.NoError(t, guard.BeginGuarded(ctx, tx, in, guardtest.Timeout))
	_, err = tx.Exec(ctx, `SELECT set_config('basalt.mode', 'PREVIEW', true)`)
	require.NoError(t, err)
	if _, err := tx.Exec(ctx, stmt); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT table_name || ' ' || op || ' cascaded=' || (detail->>'cascaded'), count(1)::int
		FROM basalt_meta.agent_ledger WHERE kind = 'ROW_CHANGE' GROUP BY 1`)
	require.NoError(t, err)
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		require.NoError(t, rows.Scan(&k, &n))
		out[k] = n
	}
	require.NoError(t, rows.Err())
	return out, nil
}

func TestCascadeCountedAndRecorded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	in := newRun(t, a, "cascade")

	// Lead 1 has notes 1 and 2; note 1 and 2 have one tag each.
	got, err := previewRows(t, a, in, `DELETE FROM public.leads WHERE id = 1`)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"public.leads DELETE cascaded=false":     1,
		"public.lead_notes DELETE cascaded=true": 2,
		"public.note_tags DELETE cascaded=true":  2,
	}, got)

	// 15 leads + 30 notes + 15 tags (notes 1..20 have tags; 1..30 here) > 50.
	_, err = previewRows(t, a, in, `DELETE FROM public.leads WHERE id <= 15`)
	requireCode(t, err, guard.CodeRowLimitExceeded)

	// SET NULL cascade into lead_owner, which the agent cannot write.
	got, err = previewRows(t, a, in, `DELETE FROM public.leads WHERE id = 101`)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"public.leads DELETE cascaded=false":     1,
		"public.lead_owner UPDATE cascaded=true": 1,
	}, got)
}
