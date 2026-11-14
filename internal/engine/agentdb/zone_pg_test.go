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
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Tag events"}
	require.NoError(t, store.StartRun(ctx, in))
	_, err := store.Write(ctx, in, sqlguard.OpUpdate, sql, nil)
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
			lines, err := engine.PreviewRevert(ctx, scope)
			require.NoError(t, err)
			requireNoSkip(t, lines)
			prep, err := engine.PrepareRevert(ctx, scope, "Undo", time.Minute)
			require.NoError(t, err)
			requireNoSkip(t, prep.Lines)

			cli := person.NewDBLedger(zonedConn(t, a.URL, zones[1]), time.Now)
			lines, err = cli.PreviewRevert(ctx, scope)
			require.NoError(t, err)
			requireNoSkip(t, lines)
			prep, err = cli.PrepareRevert(ctx, scope, "Undo")
			require.NoError(t, err)
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
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Move events"}
		require.NoError(t, store.StartRun(ctx, in))
		lines, err := store.Preview(ctx, in, update, nil, nil)
		require.NoError(t, err)
		held = append(held, lines)

		// The row images the guard stores, read back as revert lines.
		run := write(t, store, `UPDATE public.events SET note = note || '.' WHERE id = 1`)
		lines, err = store.PreviewRevert(ctx, guard.RevertScope{Kind: revert.ScopeRun, ID: run})
		require.NoError(t, err)
		requireUTC(t, lines)
	}
	for i := range held {
		requireUTC(t, held[i])
		require.Equal(t, held[0], held[i], "held lines, so rowsHash, do not depend on the zone")
		require.Equal(t, approval.RowsHash(held[0]), approval.RowsHash(held[i]))
	}
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
	res, err := r.Read(context.Background(), `SELECT at, took FROM public.events WHERE id = 1`, nil, nil)
	require.NoError(t, err)
	require.Len(t, res.Rows, 1)
	require.Equal(t, "2026-11-10T07:02:11.5Z", res.Rows[0]["at"])
	require.Equal(t, "01:30:00", res.Rows[0]["took"])
}
