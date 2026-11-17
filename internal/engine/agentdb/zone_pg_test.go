package agentdb_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// zoned is the agent's connection string with the session settings a
// client, role or database default may bring: a TimeZone, and for the
// non-UTC zone a DateStyle and IntervalStyle other than Postgres's own.
func zoned(t *testing.T, agentURL, zone string) string {
	t.Helper()
	u, err := url.Parse(agentURL)
	require.NoError(t, err)
	q := u.Query()
	q.Set("timezone", zone)
	if zone != "UTC" {
		q.Set("datestyle", "SQL,DMY")
		q.Set("intervalstyle", "iso_8601")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func zonedPool(t *testing.T, agentURL, zone string) *pgxpool.Pool {
	t.Helper()
	pool, err := agentdb.NewPool(context.Background(), zoned(t, agentURL, zone), 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var got string
	require.NoError(t, pool.QueryRow(context.Background(), "SHOW TimeZone").Scan(&got))
	require.Equal(t, zone, got, "the session starts in the client's zone")
	return pool
}

func zonedConn(t *testing.T, agentURL, zone string) *pgx.Conn {
	t.Helper()
	c, err := pgdial.Connect(context.Background(), zoned(t, agentURL, zone))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// zoneDB is a database with a guarded table of timestamptz and interval
// values, and an agent that writes it.
func zoneDB(t *testing.T) (*guardtest.DB, *guardtest.Agent) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.events (
		id bigint PRIMARY KEY, at timestamptz NOT NULL, took interval NOT NULL, note text NOT NULL);
		INSERT INTO public.events SELECT g, timestamptz '2026-11-10 06:02:11.5+00' + g * interval '1 hour',
			g * interval '90 minutes', 'note ' || g FROM generate_series(1, 4) g`)
	a := d.NewAgent(t, "bot", []string{"public.events"}, nil)
	return d, a
}

// write updates the events' notes as the engine does, from store's session.
func write(t *testing.T, store *agentdb.Store, sql string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Tag events"}
	require.NoError(t, store.StartRun(ctx, in))
	_, err := store.Write(ctx, in, action.OpUpdate, sql, nil)
	require.NoError(t, err)
	return in.RunID
}

// requireNoSkip fails on any SKIP line.
func requireNoSkip(t *testing.T, lines []string) {
	t.Helper()
	require.NotEmpty(t, lines)
	for _, text := range lines {
		l, err := revert.ParseLine(text)
		require.NoError(t, err)
		require.Equal(t, revert.ActionRestore, l.Action, "a false conflict: %s", text)
	}
}

// A write made in one session zone reverts without a false conflict from
// another, through the engine (MCP) and through basalt revert, both ways.
func TestRevertDoesNotDependOnTheSessionZone(t *testing.T) {
	t.Parallel()
	for _, zones := range [][2]string{{"Asia/Jakarta", "UTC"}, {"UTC", "Asia/Jakarta"}} {
		t.Run(zones[0]+" then "+zones[1], func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			d, a := zoneDB(t)
			signer, err := passkeytest.New(passkey.Production)
			require.NoError(t, err)
			require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, signer.Credential(), "app"))
			limits := sqlguard.DefaultLimits()
			writer := agentdb.NewStore(zonedPool(t, a.URL, zones[0]), limits, time.Now)
			run := write(t, writer, `UPDATE public.events SET note = 'tagged' WHERE id IN (1, 2)`)
			scope := guard.RevertScope{Kind: revert.ScopeRun, ID: run}

			engine := agentdb.NewStore(zonedPool(t, a.URL, zones[1]), limits, time.Now)
			pv, err := engine.PreviewRevert(ctx, action.Scope(scope), "", 10)
			require.NoError(t, err)
			requireNoSkip(t, previewTexts(pv))
			prep, err := engine.PrepareRevert(ctx, action.Scope(scope), "Undo", time.Minute)
			require.NoError(t, err)
			requireNoSkip(t, prep.Lines)

			cli := person.NewDBLedger(zonedConn(t, a.URL, zones[1]), time.Now)
			lines, err := cli.PreviewRevert(ctx, scope)
			require.NoError(t, err)
			requireNoSkip(t, lines)
			personPrep, err := cli.PrepareRevert(ctx, scope, "Undo")
			require.NoError(t, err)
			prep = action.PreparedRevert(personPrep)
			requireNoSkip(t, prep.Lines)

			// Signed, and applied from the writer's zone: Postgres
			// rebuilds the lines at apply and finds the same rowsHash.
			as, err := signer.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
			require.NoError(t, err)
			applied, err := person.NewDBLedger(zonedConn(t, a.URL, zones[0]), time.Now).ApplyRevert(ctx, prep.RevertID, as)
			require.NoError(t, err)
			require.Equal(t, 2, applied.Rows)
			require.Zero(t, applied.Skipped)
		})
	}
}

// The lines a person signs, their rowsHash and the stored row images are
// the same whatever the client's session zone and styles.
func TestSignedLinesDoNotDependOnTheSessionZone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, a := zoneDB(t)
	limits := sqlguard.DefaultLimits()
	const update = `UPDATE public.events SET note = 'moved', at = at + interval '1 day' WHERE id IN (3, 4)`
	zones := []string{"UTC", "Asia/Jakarta", "America/St_Johns"}
	held := make([][]string, 0, len(zones))
	for _, zone := range zones {
		store := agentdb.NewStore(zonedPool(t, a.URL, zone), limits, time.Now)
		in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Move events"}
		require.NoError(t, store.StartRun(ctx, in))
		lines, err := store.Preview(ctx, in, update, nil, nil)
		require.NoError(t, err)
		held = append(held, lines)

		// The row images the guard stores, read back as revert lines.
		run := write(t, store, `UPDATE public.events SET note = note || '.' WHERE id = 1`)
		pv, err := store.PreviewRevert(ctx, action.Scope{Kind: revert.ScopeRun, ID: run}, "", 10)
		require.NoError(t, err)
		requireUTC(t, previewTexts(pv))
	}
	for i := range held {
		requireUTC(t, held[i])
		require.Equal(t, held[0], held[i], "held lines, so rowsHash, do not depend on the zone")
		require.Equal(t, approval.RowsHash(held[0]), approval.RowsHash(held[i]))
	}
}

// previewTexts are the texts of a preview page's lines.
func previewTexts(pv action.PreviewPage) []string {
	out := make([]string, 0, len(pv.Page))
	for _, l := range pv.Page {
		out = append(out, l.Text)
	}
	return out
}

// requireUTC fails unless lines print timestamptz values in UTC and
// intervals in the postgres style.
func requireUTC(t *testing.T, lines []string) {
	t.Helper()
	all := strings.Join(lines, "\n")
	require.Contains(t, all, "+00:00", "timestamptz values in UTC")
	require.NotContains(t, all, "+07:00")
	require.NotContains(t, all, "-03:30")
	require.Contains(t, all, ":30:00", "intervals in the postgres style")
	require.NotContains(t, all, "PT")
}

// query returns timestamptz values in the contract's form whatever the
// session's DateStyle.
func TestQueryDoesNotDependOnTheSessionStyle(t *testing.T) {
	t.Parallel()
	_, a := zoneDB(t)
	r := agentdb.NewReader(zonedPool(t, a.URL, "Asia/Jakarta"), sqlguard.DefaultLimits(), time.Now)
	res, err := r.Read(context.Background(), `SELECT at, took FROM public.events WHERE id = 1`, nil, action.Statement{})
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, "2026-11-10T07:02:11.5Z", res.Rows[0]["at"])
	require.Equal(t, "01:30:00", res.Rows[0]["took"])
}

// A write that skips the engine (the agent's credential used directly, as
// in psql) from a session in Asia/Jakarta, in other date and interval
// styles and with extra_float_digits 0, stores the same row images as the
// same write through the engine, and reverts from the engine without a
// false conflict. The guard's trigger sets the session settings only while
// it runs: the agent's own SQL after the write still sees its own.
func TestAWriteThatSkipsTheEngineStoresTheEngineImages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.readings (
		id bigint PRIMARY KEY, at timestamptz NOT NULL, took interval NOT NULL,
		ratio float8 NOT NULL, price money NOT NULL, note text NOT NULL);
		INSERT INTO public.readings SELECT g, timestamptz '2026-11-10 06:02:11.5+00', interval '90 minutes',
			0.1::float8 + 0.2::float8, 1234.5, 'note' FROM generate_series(1, 4) g`)
	tables := []string{"public.readings"}
	a := d.NewAgent(t, "bot", tables, tables)
	signer, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, signer.Credential(), "app"))

	u, err := url.Parse(zoned(t, a.URL, "Asia/Jakarta"))
	require.NoError(t, err)
	q := u.Query()
	q.Set("extra_float_digits", "0")
	u.RawQuery = q.Encode()
	direct, err := pgdial.Connect(ctx, u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = direct.Close(context.Background()) })

	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Tag readings by hand"}
	require.NoError(t, guard.StartRun(ctx, direct, in))
	require.NoError(t, pgx.BeginFunc(ctx, direct, func(tx pgx.Tx) error {
		require.NoError(t, guard.BeginGuarded(ctx, tx, in, guardtest.Timeout))
		if _, err := tx.Exec(ctx, `UPDATE public.readings SET note = 'tagged' WHERE id IN (1, 2)`); err != nil {
			return err
		}
		if _, err := guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: "UPDATE"}); err != nil {
			return err
		}
		// The trigger ran; the agent's session settings are its own again.
		var zone, digits, at, ratio string
		require.NoError(t, tx.QueryRow(ctx, `SELECT current_setting('TimeZone'), current_setting('extra_float_digits'),
			at::text, ratio::text FROM public.readings WHERE id = 1`).Scan(&zone, &digits, &at, &ratio))
		require.Equal(t, "Asia/Jakarta", zone)
		require.Equal(t, "0", digits)
		require.Equal(t, "10/11/2026 13:02:11.5 WIB", at)
		require.Equal(t, "0.3", ratio)
		return nil
	}))

	engine := agentdb.NewStore(zonedPool(t, a.URL, "UTC"), sqlguard.DefaultLimits(), time.Now)
	viaEngine := write(t, engine, `UPDATE public.readings SET note = 'tagged' WHERE id IN (3, 4)`)

	// The images, without the key, are the same either way.
	direct2 := images(t, d, in.RunID)
	require.Len(t, direct2, 2)
	require.Equal(t, images(t, d, viaEngine), direct2)
	all := strings.Join(direct2, "\n")
	require.Contains(t, all, `"at": "2026-11-10T06:02:11.5+00:00"`)
	require.Contains(t, all, `"took": "01:30:00"`)
	require.Contains(t, all, `"ratio": 0.30000000000000004`)

	// The engine reverts the direct write without a false conflict.
	scope := guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}
	pv, err := engine.PreviewRevert(ctx, action.Scope(scope), "", 10)
	require.NoError(t, err)
	requireNoSkip(t, previewTexts(pv))
	prep, err := engine.PrepareRevert(ctx, action.Scope(scope), "Undo", time.Minute)
	require.NoError(t, err)
	requireNoSkip(t, prep.Lines)
	as, err := signer.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := person.NewDBLedger(zonedConn(t, a.URL, "UTC"), time.Now).ApplyRevert(ctx, prep.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, 2, applied.Rows)
	require.Zero(t, applied.Skipped)
}

// images is the old and new row images, without id, the guard stored for
// run's row changes, in ledger order.
func images(t *testing.T, d *guardtest.DB, run uuid.UUID) []string {
	t.Helper()
	// Plain SQL: a fixture read of the ledger as the admin.
	rows, err := d.Admin.Query(context.Background(), `SELECT (l.old_row - 'id')::text || ' -> ' || (l.new_row - 'id')::text
		FROM basalt_meta.ledger l JOIN basalt_meta.changes c ON c.change_id = l.change_id
		WHERE c.run_id = $1 AND l.kind = 'ROW_CHANGE' ORDER BY l.seq`, run)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// handConn is the agent's own connection, as in psql, from Asia/Jakarta,
// with intervals in iso_8601, extra_float_digits 0 and bytea_output escape:
// no setting the engine pins has its value but DateStyle's ISO, which the
// Go callers need to read the timestamps the guard functions return
// (ISO, DMY: the order differs).
func handConn(t *testing.T, agentURL string) *pgx.Conn {
	t.Helper()
	u, err := url.Parse(zoned(t, agentURL, "Asia/Jakarta"))
	require.NoError(t, err)
	q := u.Query()
	q.Set("extra_float_digits", "0")
	q.Set("bytea_output", "escape")
	q.Set("datestyle", "ISO,DMY")
	u.RawQuery = q.Encode()
	c, err := pgdial.Connect(context.Background(), u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// blobDB is a guarded table with a bytea column next to the zone and float
// ones, four rows alike but for id, and an agent that writes it.
func blobDB(t *testing.T) (*guardtest.DB, *guardtest.Agent, *passkeytest.Authenticator) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.files (
		id bigint PRIMARY KEY, at timestamptz NOT NULL, took interval NOT NULL,
		ratio float8 NOT NULL, body bytea NOT NULL, note text NOT NULL);
		INSERT INTO public.files SELECT g, timestamptz '2026-11-10 06:02:11.5+00', interval '90 minutes',
			0.1::float8 + 0.2::float8, '\x00ff41'::bytea, 'note' FROM generate_series(1, 4) g`)
	tables := []string{"public.files"}
	a := d.NewAgent(t, "bot", tables, tables)
	signer, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, signer.Credential(), "app"))
	return d, a, signer
}

// A write that skips the engine with bytea_output escape stores the bytea
// column as the engine does (hex), and the engine reverts it cleanly.
func TestAWriteThatSkipsTheEngineStoresByteaAsTheEngine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, a, signer := blobDB(t)
	direct := handConn(t, a.URL)
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Tag files by hand"}
	require.NoError(t, guard.StartRun(ctx, direct, in))
	require.NoError(t, guardtest.Guarded(ctx, direct, in, `UPDATE public.files SET note = 'tagged' WHERE id IN (1, 2)`))
	var shown string
	require.NoError(t, direct.QueryRow(ctx, `SELECT body::text FROM public.files WHERE id = 1`).Scan(&shown))
	require.Equal(t, `\000\377A`, shown, "the agent's session keeps its bytea_output")

	engine := agentdb.NewStore(zonedPool(t, a.URL, "UTC"), sqlguard.DefaultLimits(), time.Now)
	viaEngine := write(t, engine, `UPDATE public.files SET note = 'tagged' WHERE id IN (3, 4)`)
	got := images(t, d, in.RunID)
	require.Len(t, got, 2)
	require.Equal(t, images(t, d, viaEngine), got)
	require.Contains(t, strings.Join(got, "\n"), `"body": "\\x00ff41"`)

	scope := guard.RevertScope{Kind: revert.ScopeRun, ID: in.RunID}
	prep, err := engine.PrepareRevert(ctx, action.Scope(scope), "Undo", time.Minute)
	require.NoError(t, err)
	requireNoSkip(t, prep.Lines)
	as, err := signer.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := person.NewDBLedger(zonedConn(t, a.URL, "UTC"), time.Now).ApplyRevert(ctx, prep.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, 2, applied.Rows)
	require.Zero(t, applied.Skipped)
}

// The revert functions called by hand, from a session in none of the
// engine's settings, find no false conflict with a write through the
// engine, and restore the rows as they were.
func TestRevertFunctionsCalledByHandDoNotDependOnTheSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, a, signer := blobDB(t)
	engine := agentdb.NewStore(zonedPool(t, a.URL, "UTC"), sqlguard.DefaultLimits(), time.Now)
	run := write(t, engine, `UPDATE public.files SET note = 'tagged', ratio = ratio * 3, body = body || '\x01'::bytea,
		at = at + interval '1 day', took = took * 2 WHERE id IN (1, 2)`)

	hand := handConn(t, a.URL)
	scope := guard.RevertScope{Kind: revert.ScopeRun, ID: run}
	lines, err := guard.PreviewRevert(ctx, hand, scope)
	require.NoError(t, err)
	requireNoSkip(t, lines)
	prep, err := guard.PrepareRevert(ctx, hand, scope, "Undo by hand")
	require.NoError(t, err)
	requireNoSkip(t, prep.Lines)
	as, err := signer.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, hand, prep.RevertID, as)
	require.NoError(t, err)
	require.Equal(t, 2, applied.Rows)
	require.Zero(t, applied.Skipped)

	var same int
	// Plain SQL: a fixture read as the admin.
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(*)::int FROM public.files a JOIN public.files b ON b.id = 3
		WHERE a.id IN (1, 2) AND (a.at, a.took, a.ratio, a.body, a.note) = (b.at, b.took, b.ratio, b.body, b.note)`).Scan(&same))
	require.Equal(t, 2, same, "the reverted rows are as they were")
}
