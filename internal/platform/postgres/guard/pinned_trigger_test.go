package guard_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// pinnedFunctions are the guard functions that build or parse row images
// and run with the engine's pinned settings (versions 34 and 35).
var pinnedFunctions = []string{
	"basalt_meta.guard_row()",
	"basalt_meta._revert_fetch(oid, jsonb, boolean)",
	"basalt_meta._revert_write(basalt_meta.revert_item)",
}

// configOf is fn's SET clauses, as Postgres records them.
func configOf(t *testing.T, d *guardtest.DB, fn string) []string {
	t.Helper()
	var config []string
	// Plain SQL: a catalog read.
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT coalesce(proconfig, '{}') FROM pg_proc
		WHERE oid = $1::regprocedure`, fn).Scan(&config))
	return config
}

// guard_row and the revert's row read and restore run with the settings
// the engine pins in its own transactions, besides search_path, so a row
// image does not depend on the session that wrote or reverts it.
func TestGuardPinsTheSessionSettings(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	want := []string{
		"search_path=pg_catalog, pg_temp",
		"TimeZone=" + guard.PinnedTimeZone,
		"DateStyle=" + guard.PinnedDateStyle,
		"IntervalStyle=" + guard.PinnedIntervalStyle,
		"extra_float_digits=" + guard.PinnedExtraFloatDigits,
		"lc_monetary=" + guard.PinnedLcMonetary,
		"bytea_output=" + guard.PinnedByteaOutput,
	}
	for _, fn := range pinnedFunctions {
		require.ElementsMatch(t, want, configOf(t, d, fn), fn)
	}

	// The trigger still runs as the agent's write: one row change.
	in := newRun(t, a, "Rename a lead")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, `UPDATE public.leads SET name = 'Ada' WHERE id = 1`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(l.seq)::int FROM basalt_meta.ledger l
		JOIN basalt_meta.changes c ON c.change_id = l.change_id WHERE c.run_id = $1 AND l.kind = 'ROW_CHANGE'`, in.RunID))
}

// The pins hold only while guard_row runs: Postgres restores the session's
// values when it returns, so a setting the agent's transaction made, with
// SET LOCAL or set_config, is the same after its write fired the trigger.
func TestGuardRowLeavesTheSessionSettings(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	ctx := context.Background()
	in := newRun(t, a, "Rename a lead")
	require.NoError(t, pgx.BeginFunc(ctx, a.Conn, func(tx pgx.Tx) error {
		require.NoError(t, guard.BeginGuarded(ctx, tx, in, guardtest.Timeout))
		_, err := tx.Exec(ctx, `SET LOCAL TimeZone = 'Asia/Jakarta'; SET LOCAL DateStyle = 'SQL, DMY';
			SET LOCAL IntervalStyle = 'iso_8601'; SET LOCAL extra_float_digits = 0; SET LOCAL lc_monetary = 'POSIX'; SET LOCAL bytea_output = 'escape'`)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `UPDATE public.leads SET name = 'Ada' WHERE id = 1`)
		require.NoError(t, err)
		var got []string
		require.NoError(t, tx.QueryRow(ctx, `SELECT ARRAY[current_setting('TimeZone'), current_setting('DateStyle'),
			current_setting('IntervalStyle'), current_setting('extra_float_digits'), current_setting('lc_monetary'), current_setting('bytea_output')]`).Scan(&got))
		require.Equal(t, []string{"Asia/Jakarta", "SQL, DMY", "iso_8601", "0", "POSIX", "escape"}, got)
		_, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: "UPDATE"})
		return err
	}))
}
