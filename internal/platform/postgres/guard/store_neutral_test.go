package guard_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// asObject parses one text the guard wrote.
func asObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &m))
	return m
}

// A held write's binding and lines are store-neutral (CONTRACT.md, Stores,
// What every store writes): the store, the request by family, the agent as
// agent:<name>, and each line's shape, store and resource.
func TestStoreNeutralApprovalTexts(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Close stale leads")
	stmt := `UPDATE public.leads SET status = $1 WHERE id <= 12`
	held, lines := previewAndHold(t, a.Conn, in, stmt, []any{"closed"}, []string{"status"})

	b := asObject(t, held.BindingText)
	require.Equal(t, map[string]any{"kind": "POSTGRES", "name": scalarOf[string](t, d.Admin, `SELECT current_database()::text`)}, b["store"])
	require.Equal(t, a.Name, b["agent"])
	require.Equal(t, map[string]any{"kind": "SQL", "statement": stmt, "params": []any{"closed"}}, b["request"])
	require.Equal(t, []any{"status"}, b["assignedFields"])
	for _, k := range []string{"database", "statement", "params", "assignedColumns"} {
		require.NotContains(t, b, k)
	}
	require.Len(t, lines, 12)
	for _, text := range lines {
		l := asObject(t, text)
		require.Equal(t, "RECORD", l["shape"])
		require.Equal(t, map[string]any{"kind": "POSTGRES", "verb": "UPDATE"}, l["store"])
		require.Equal(t, "public.leads", l["resource"])
		require.NotContains(t, l, "table")
	}
	require.Equal(t, "public.leads", scalarOf[string](t, a.Conn,
		`SELECT table_name FROM basalt_meta.agent_changes WHERE approval_id = $1`, held.ApprovalID))
}

// A revert's binding and lines are store-neutral: the store, the select
// with agent:<name> and resources, requestedBy, and each line's shape,
// store (with code) and resource.
func TestStoreNeutralRevertTexts(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Mark two leads")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'm' WHERE id IN (3, 4)`))
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo it")
	require.NoError(t, err)

	b := asObject(t, prep.BindingText)
	require.Equal(t, "POSTGRES", b["store"].(map[string]any)["kind"])
	require.Equal(t, a.Name, b["requestedBy"])
	require.Equal(t, map[string]any{
		"scope": "RUN", "scopeId": in.RunID.String(), "agents": []any{a.Name}, "runs": nil, "resources": nil,
	}, b["select"])
	require.NotContains(t, b, "database")
	require.Len(t, prep.Lines, 2)
	for _, text := range prep.Lines {
		l := asObject(t, text)
		require.Equal(t, "RECORD", l["shape"])
		require.Equal(t, map[string]any{"kind": "POSTGRES", "verb": "UPDATE", "code": nil}, l["store"])
		require.Equal(t, "public.leads", l["resource"])
		require.NotContains(t, l, "table")
		require.NotContains(t, l, "sqlState")
	}

	// The agent sees its select as texts carry it; the guard keeps roles.
	require.Equal(t, a.Name, scalarOf[string](t, a.Conn,
		`SELECT selection -> 'agents' ->> 0 FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID))
	require.Equal(t, a.Role, scalarOf[string](t, d.Admin,
		`SELECT selection -> 'agents' ->> 0 FROM basalt_meta.reverts WHERE revert_id = $1`, prep.RevertID))
	require.Equal(t, a.Name, scalarOf[string](t, a.Conn, `SELECT basalt_meta.agent_name()`))
}

// The ledger stores Basalt's op (READ for a read) and the store's verb
// from its first entry, and the chain hashes them.
func TestStoreNeutralLedgerFields(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Read then write")
	read := readLeads(t, a, in, 1)
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'x' WHERE id = 150`))

	require.Equal(t, "READ SELECT", scalarOf[string](t, d.Admin,
		`SELECT op || ' ' || verb FROM basalt_meta.ledger WHERE kind = 'READ' AND change_id = $1`, read))
	require.Equal(t, "READ", scalarOf[string](t, d.Admin, `SELECT op FROM basalt_meta.changes WHERE change_id = $1`, read))
	require.Equal(t, "UPDATE UPDATE", scalarOf[string](t, d.Admin,
		`SELECT op || ' ' || verb FROM basalt_meta.ledger WHERE kind = 'ROW_CHANGE' AND row_key = '{"id": 150}'::jsonb`))
	requireIntact(t, a.Conn)

	// The chain covers verb: changing it breaks the chain.
	d.Exec(t, `UPDATE basalt_meta.ledger SET verb = 'MERGE' WHERE kind = 'ROW_CHANGE' AND row_key = '{"id": 150}'::jsonb`)
	st, err := guard.VerifyChain(context.Background(), a.Conn)
	require.NoError(t, err)
	require.False(t, st.Intact)
}

// An install from before version 10 upgrades with no row rewritten and
// its agents get their names. Clean state: the chain does not verify the
// rows hashed before the upgrade, so such an install reinstalls.
func TestStoreNeutralUpgradeNamesTheAgents(t *testing.T) {
	ctx := context.Background()
	restore := guardtest.UpToVersion(t, guard.StoreNeutralVersion-1)
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Before the upgrade")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'b' WHERE id = 5`))
	before := count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger`)
	requireIntact(t, a.Conn)

	// A superuser is a member of every role, so naming it by the rule
	// would make it an agent: the migration leaves it out.
	root := d.Names.AgentPrefix() + "root"
	d.Exec(t, "CREATE ROLE "+pgx.Identifier{root}.Sanitize()+" SUPERUSER")
	t.Cleanup(func() { d.Exec(t, "DROP ROLE IF EXISTS "+pgx.Identifier{root}.Sanitize()) })

	restore()
	// Version 10's SQL alone, so the names come from the migration and not
	// from basalt init setting the agent up again.
	d.Exec(t, "BEGIN; SET LOCAL ROLE "+d.Names.Guard()+"; SET LOCAL search_path = pg_catalog, pg_temp;"+guard.StoreNeutralSQL(d.Names)+"COMMIT;")
	require.Equal(t, "bot", scalarOf[string](t, d.Admin, `SELECT name FROM basalt_meta.agent_names WHERE role = $1`, a.Role),
		"the migration records the agents set up before it")
	require.Zero(t, count(t, d.Admin, `SELECT count(role)::int FROM basalt_meta.agent_names WHERE role = $1`, root),
		"a superuser is never named an agent")
	require.Equal(t, before, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger`), "no row is written or rewritten")
	st, err := guard.VerifyChain(ctx, a.Conn)
	require.NoError(t, err)
	require.False(t, st.Intact, "rows hashed before the upgrade do not verify in the new form")
}

// verb is the request's own command, not the first row's op: an INSERT ...
// ON CONFLICT whose rows all update is op UPDATE and verb INSERT, on its
// CHANGE row and on a held write's APPROVAL_PENDING row.
func TestStoreNeutralVerbIsTheRequestsCommand(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Upsert a lead")
	upsert := `INSERT INTO public.leads (id, name) VALUES (5, 'five') ON CONFLICT (id) DO UPDATE SET name = excluded.name`
	var change uuid.UUID
	require.NoError(t, pgx.BeginFunc(ctx, a.Conn, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in, guardtest.Timeout); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, upsert); err != nil {
			return err
		}
		var err error
		change, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "INSERT", Statement: upsert})
		return err
	}))
	require.Equal(t, "UPDATE INSERT", scalarOf[string](t, d.Admin,
		`SELECT op || ' ' || verb FROM basalt_meta.ledger WHERE kind = 'CHANGE' AND change_id = $1`, change))
	requireIntact(t, a.Conn)

	tx, err := a.Conn.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.BeginPreview(ctx, tx, in, guardtest.Timeout))
	_, err = tx.Exec(ctx, upsert)
	require.NoError(t, err)
	lines, err := guard.PreviewLines(ctx, tx, []string{"id", "name"})
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	held, err := guard.Hold(ctx, a.Conn, in, guardtest.Timeout, guard.HoldRequest{Verb: "INSERT", Statement: upsert, Assigned: []string{"id", "name"}, Lines: lines})
	require.NoError(t, err)
	require.Equal(t, "UPDATE INSERT", scalarOf[string](t, d.Admin,
		`SELECT op || ' ' || verb FROM basalt_meta.ledger WHERE kind = 'APPROVAL_PENDING' AND detail ->> 'approvalId' = $1`, held.ApprovalID.String()))

	// A command outside INSERT, UPDATE and DELETE is refused, never replaced
	// by the first line's op.
	_, err = guard.Hold(ctx, a.Conn, in, guardtest.Timeout, guard.HoldRequest{Verb: "SELECT", Statement: upsert, Assigned: []string{"id", "name"}, Lines: lines})
	require.Error(t, err)
	require.Equal(t, "BS008", guardtest.SQLState(err))
}

// agent_reverts never leaves out a selected agent it cannot name: a role
// with no recorded name is refused (UNKNOWN_AGENT).
func TestAgentRevertsRefusesAnUnnamedAgent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "Mark a lead")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET status = 'm' WHERE id = 3`))
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, action.Scope{Kind: revert.ScopeRun, ID: in.RunID}, "Undo it")
	require.NoError(t, err)

	d.Exec(t, `DELETE FROM basalt_meta.agent_names WHERE role = '`+a.Role+`'`)
	var selection []byte
	err = a.Conn.QueryRow(context.Background(), `SELECT selection FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID).Scan(&selection)
	require.Error(t, err, "a selection that names an agent with no name is refused, never shortened")
	require.Equal(t, "BS007", guardtest.SQLState(err))
}
