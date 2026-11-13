package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// TestGuardedTransactionIgnoresTheRolesOwnTimeouts: the agent role can
// ALTER ROLE CURRENT_USER SET its own defaults, statement_timeout 0
// included. A guarded transaction sets its own timeouts, so a session
// that starts with the role's settings still runs within the engine's.
func TestGuardedTransactionIgnoresTheRolesOwnTimeouts(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER ROLE CURRENT_USER SET statement_timeout = 0`,
		`ALTER ROLE CURRENT_USER SET lock_timeout = '1ms'`,
		`ALTER ROLE CURRENT_USER SET idle_in_transaction_session_timeout = 0`,
	} {
		_, err := a.Conn.Exec(ctx, stmt)
		require.NoError(t, err, "the role can change its own defaults; the guarded transaction must not rely on them")
	}
	fresh, err := pgdial.Connect(ctx, a.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fresh.Close(context.Background()) })
	var before string
	require.NoError(t, fresh.QueryRow(ctx, `SHOW statement_timeout`).Scan(&before))
	require.Equal(t, "0", before, "a new session starts with the role's setting")

	in := newRun(t, a, "check timeouts")
	timeout := 1500 * time.Millisecond
	got := map[string]string{}
	err = pgx.BeginFunc(ctx, fresh, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(ctx, tx, in, timeout); err != nil {
			return err
		}
		for _, name := range []string{"statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout"} {
			var v string
			if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting($1)`, name).Scan(&v); err != nil {
				return err
			}
			got[name] = v
		}
		_, err := tx.Exec(ctx, `SELECT pg_catalog.pg_sleep(3)`)
		return err
	})
	require.Equal(t, map[string]string{
		"statement_timeout": "1500ms", "lock_timeout": "1500ms", "idle_in_transaction_session_timeout": "1500ms",
	}, got)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "57014", pe.Code, "the statement runs within the guarded timeout")

	var after string
	require.NoError(t, fresh.QueryRow(ctx, `SHOW statement_timeout`).Scan(&after))
	require.Equal(t, "0", after, "the settings are transaction-local")
}

func TestBeginGuardedNeedsATimeout(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	in := newRun(t, a, "no timeout")
	err := pgx.BeginFunc(context.Background(), a.Conn, func(tx pgx.Tx) error {
		return guard.BeginGuarded(context.Background(), tx, in, 0)
	})
	require.ErrorIs(t, err, guard.ErrInvalidIntent)
}
