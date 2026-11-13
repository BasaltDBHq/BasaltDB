package guard_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// readLeads reads the given leads as the agent and records the read in the
// run with the version of each row, as the engine does.
func readLeads(t *testing.T, a *guardtest.Agent, in guard.Intent, ids ...int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	versions := make([]guard.RowVersion, 0, len(ids))
	for _, id := range ids {
		var v guard.RowVersion
		// Plain SQL: the shape the engine's rewritten read returns.
		require.NoError(t, a.Conn.QueryRow(ctx, `SELECT 'public.leads'::regclass::oid, jsonb_build_object('id', id), xmin::text
			FROM public.leads WHERE id = $1`, id).Scan(&v.TableOID, &v.Key, &v.Version))
		versions = append(versions, v)
	}
	change, err := guard.RecordRead(ctx, a.Conn, guard.Read{
		RunID: in.RunID, Statement: "SELECT * FROM leads WHERE id = ANY($1)", Params: []any{ids},
		Tables: []string{"leads"}, Rows: len(ids), Versions: versions,
	})
	require.NoError(t, err)
	return change
}

// rowDetail is the detail of the ROW_CHANGE rows on table for key id, oldest first.
func rowDetails(t *testing.T, d *guardtest.DB, table string, id int) []map[string]any {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `SELECT detail FROM basalt_meta.ledger
		WHERE kind = 'ROW_CHANGE' AND table_name = $1 AND row_key = jsonb_build_object('id', $2::bigint) ORDER BY seq`, table, id)
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var m map[string]any
		require.NoError(t, rows.Scan(&m))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

func status(t *testing.T, d *guardtest.DB, id int) string {
	t.Helper()
	var s string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT status FROM public.leads WHERE id = $1`, id).Scan(&s))
	return s
}

func TestStaleReadRefusesAChangedRow(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Close stale leads")
	readLeads(t, a, in, 20)

	// A person edits the lead after the run read it.
	d.Exec(t, `UPDATE public.leads SET status = 'won' WHERE id = 20`)

	err := guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'lost' WHERE id = 20`)
	requireCode(t, err, guard.CodeStaleRead)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Contains(t, pg.Detail, `public.leads {"id": 20} read at xmin `)
	require.Contains(t, pg.Detail, ", now ")
	require.Equal(t, "won", status(t, d, 20), "the stale write never landed")

	// A stale DELETE says STALE_READ, not APPROVAL_REQUIRED.
	err = guardtest.Guarded(ctx, a.Conn, in, `DELETE FROM public.leads WHERE id = 20`)
	requireCode(t, err, guard.CodeStaleRead)

	// Reading again catches up.
	readLeads(t, a, in, 20)
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'lost' WHERE id = 20`))
}

func TestReadThenWriteRecordsBasedOn(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Merge duplicates")
	read := readLeads(t, a, in, 4)
	var version string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT xmin::text FROM public.leads WHERE id = 4`).Scan(&version))

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET status = 'merged' WHERE id = 4`))
	det := rowDetails(t, d, "public.leads", 4)
	require.Len(t, det, 1)
	require.Equal(t, map[string]any{"version": "xmin:" + version, "changeId": read.String()}, det[0]["basedOn"])
	require.NotContains(t, det[0], "blindWrite")

	// The run's own write moves its known version: a second write is not stale.
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 99 WHERE id = 4`))
	det = rowDetails(t, d, "public.leads", 4)
	require.Len(t, det, 2)
	based, ok := det[1]["basedOn"].(map[string]any)
	require.True(t, ok, "%v", det[1])
	require.NotEqual(t, "xmin:"+version, based["version"])
}

func TestRowChangeRecordsNewXmin(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Versions for revert")

	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET score = 3 WHERE id = 8`))
	det := rowDetails(t, d, "public.leads", 8)
	require.Len(t, det, 1)
	var now string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT xmin::text FROM public.leads WHERE id = 8`).Scan(&now))
	require.Equal(t, now, det[0]["newXmin"], "the version the write left")
	require.NotEqual(t, det[0]["xmin"], det[0]["newXmin"])

	// A cascaded row records it too (lead 101 SET NULLs lead_owner 1).
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))
	owner := rowDetails(t, d, "public.lead_owner", 1)
	require.Len(t, owner, 1)
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT xmin::text FROM public.lead_owner WHERE id = 1`).Scan(&now))
	require.Equal(t, now, owner[0]["newXmin"])
}

func TestBlindWriteIsAllowedAndMarked(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Renumber a lead")

	// Lead 101 was never read; updating its id cascades SET NULL to lead_owner.
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `UPDATE public.leads SET id = 9101 WHERE id = 101`))
	det := rowDetails(t, d, "public.leads", 101)
	require.Len(t, det, 1)
	require.Equal(t, true, det[0]["blindWrite"])
	require.NotContains(t, det[0], "basedOn")
	owner := rowDetails(t, d, "public.lead_owner", 1)
	require.Len(t, owner, 1)
	require.NotContains(t, owner[0], "blindWrite", "cascaded rows are not blind writes")
	require.Zero(t, count(t, d.Admin, `SELECT count(run_id)::int FROM basalt_meta.reads WHERE table_oid = 'public.lead_owner'::regclass`),
		"cascaded rows are not tracked for the run")
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(run_id)::int FROM basalt_meta.reads WHERE row_key = '{"id": 9101}'`),
		"the run knows the row it wrote, under its new key")

	// An INSERT is neither.
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, in, `INSERT INTO public.leads (id, name) VALUES (5000, 'new')`))
	det = rowDetails(t, d, "public.leads", 5000)
	require.Len(t, det, 1)
	require.NotContains(t, det[0], "blindWrite")
	require.NotContains(t, det[0], "basedOn")
}

func TestReadsBelongToTheirRun(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	first := newRun(t, a, "Look at lead 7")
	readLeads(t, a, first, 7)
	d.Exec(t, `UPDATE public.leads SET status = 'won' WHERE id = 7`)

	other := newRun(t, a, "Another run")
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, other, `UPDATE public.leads SET score = 5 WHERE id = 7`),
		"another run's reads do not apply")
	err := guardtest.Guarded(ctx, a.Conn, first, `UPDATE public.leads SET score = 6 WHERE id = 7`)
	requireCode(t, err, guard.CodeStaleRead)
}

func TestRecordReadWritesAChangeAndALedgerRow(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Count open leads")
	change := readLeads(t, a, in, 1, 2, 3)

	var op, st, intent string
	var rows int
	require.NoError(t, a.Conn.QueryRow(ctx, `SELECT op, status, intent, rows FROM basalt_meta.agent_changes WHERE change_id = $1`,
		change).Scan(&op, &st, &intent, &rows))
	require.Equal(t, []any{"SELECT", "APPLIED", "Count open leads", 3}, []any{op, st, intent, rows})

	var detail map[string]any
	require.NoError(t, a.Conn.QueryRow(ctx, `SELECT detail FROM basalt_meta.agent_ledger WHERE kind = 'READ' AND change_id = $1`,
		change).Scan(&detail))
	require.Equal(t, in.RunID.String(), detail["runId"])
	require.Equal(t, []any{"leads"}, detail["tables"])
	versions, ok := detail["versions"].([]any)
	require.True(t, ok)
	require.Len(t, versions, 3)
	first, ok := versions[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "public.leads", first["table"])
	require.Regexp(t, `^xmin:[0-9]+$`, first["version"])
	requireIntact(t, a.Conn)

	// A read outside a run is recorded too, with no run.
	outside, err := guard.RecordRead(ctx, a.Conn, guard.Read{Statement: "SELECT count(id) FROM leads", Tables: []string{"leads"}, Rows: 1})
	require.NoError(t, err)
	require.Equal(t, 1, count(t, a.Conn, `SELECT count(1)::int FROM basalt_meta.agent_changes WHERE change_id = $1 AND run_id IS NULL`, outside))
}

func TestBigReadsAreNotCountedAsWrites(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	in := newRun(t, a, "Read many")
	ids := make([]int, 0, 120)
	for i := 1; i <= 120; i++ {
		ids = append(ids, i)
	}
	readLeads(t, a, in, ids...)
}

func TestRecordReadValidates(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, []string{"public.payroll"})
	b := d.NewAgent(t, "other", leads, nil)
	ctx := context.Background()
	in := newRun(t, a, "Read")
	theirs := newRun(t, b, "Theirs")
	oid := func(table string) uint32 {
		var o uint32
		require.NoError(t, d.Admin.QueryRow(ctx, `SELECT $1::regclass::oid`, table).Scan(&o))
		return o
	}
	good := guard.RowVersion{TableOID: oid("public.leads"), Key: json.RawMessage(`{"id": 1}`), Version: "123"}

	_, err := guard.RecordRead(ctx, a.Conn, guard.Read{RunID: theirs.RunID, Statement: "SELECT 1", Versions: []guard.RowVersion{good}})
	requireCode(t, err, guard.CodeNotAllowed)

	cases := map[string]guard.RowVersion{
		"unguarded table":  {TableOID: oid("public.payroll"), Key: json.RawMessage(`{"id": 1}`), Version: "1"},
		"unreadable table": {TableOID: oid("public.lead_notes"), Key: json.RawMessage(`{"id": 1}`), Version: "1"},
		"wrong key":        {TableOID: good.TableOID, Key: json.RawMessage(`{"name": "x"}`), Version: "1"},
		"extra key":        {TableOID: good.TableOID, Key: json.RawMessage(`{"id": 1, "name": "x"}`), Version: "1"},
		"key not object":   {TableOID: good.TableOID, Key: json.RawMessage(`[1]`), Version: "1"},
		"bad version":      {TableOID: good.TableOID, Key: good.Key, Version: "xmin:1"},
		"version too big":  {TableOID: good.TableOID, Key: good.Key, Version: "4294967296"},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := guard.RecordRead(ctx, a.Conn, guard.Read{RunID: in.RunID, Statement: "SELECT 1", Versions: []guard.RowVersion{v}})
			requireCode(t, err, guard.CodeLedgerInputInvalid)
		})
	}
	_, err = guard.RecordRead(ctx, a.Conn, guard.Read{RunID: in.RunID, Statement: "", Versions: nil})
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	_, err = guard.RecordRead(ctx, a.Conn, guard.Read{RunID: in.RunID, Statement: "SELECT 1", Rows: -1})
	requireCode(t, err, guard.CodeLedgerInputInvalid)

	// The same row twice in one read (a self-join) is fine.
	_, err = guard.RecordRead(ctx, a.Conn, guard.Read{RunID: in.RunID, Statement: "SELECT 1", Versions: []guard.RowVersion{good, good}})
	require.NoError(t, err)

	// Agents still cannot write reads directly.
	_, err = a.Conn.Exec(ctx, `INSERT INTO basalt_meta.reads (run_id, table_oid, row_key, row_version) VALUES ($1, 1, '{}', '1')`, in.RunID)
	require.Equal(t, "42501", guardtest.SQLState(err))
	_, err = a.Conn.Exec(ctx, `SELECT * FROM basalt_meta.reads`)
	require.Equal(t, "42501", guardtest.SQLState(err))
}

func TestReadsGoWithTheirRun(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	in := newRun(t, a, "Old run")
	readLeads(t, a, in, 1, 2)
	require.Equal(t, 2, count(t, d.Admin, `SELECT count(run_id)::int FROM basalt_meta.reads`))
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	require.Zero(t, count(t, d.Admin, `SELECT count(run_id)::int FROM basalt_meta.reads`))
	requireIntact(t, a.Conn)
}

func TestResolveGuarded(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `CREATE VIEW public.open_leads AS SELECT * FROM public.leads WHERE status = 'open'`)
	a := d.NewAgent(t, "bot", leads, []string{"public.payroll", "public.open_leads"})
	ctx := context.Background()

	got, err := guard.ResolveGuarded(ctx, a.Conn, []string{
		`"leads"`, `public.leads`, `public.payroll`, `public.open_leads`,
		`public.lead_notes`, `public.missing`,
	})
	require.NoError(t, err)
	var leadsOID uint32
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT 'public.leads'::regclass::oid`).Scan(&leadsOID))
	want := guard.GuardedTable{Table: "public.leads", OID: leadsOID, PKCols: []string{"id"}}
	require.Equal(t, map[string]guard.GuardedTable{`"leads"`: want, `public.leads`: want}, got,
		"views, unguarded, unreadable and missing tables are left out")

	none, err := guard.ResolveGuarded(ctx, a.Conn, nil)
	require.NoError(t, err)
	require.Empty(t, none)
}
