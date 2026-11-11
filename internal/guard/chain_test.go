package guard_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

// writeSome makes n single-row agent writes (each one ROW_CHANGE and one
// CHANGE ledger row) after one RUN_STARTED row.
func writeSome(t *testing.T, a *guardtest.Agent, n int) {
	t.Helper()
	ctx := context.Background()
	in := newRun(t, a, "chain")
	for i := 1; i <= n; i++ {
		require.NoError(t, guardtest.Guarded(ctx, a.Conn, in,
			fmt.Sprintf(`UPDATE public.leads SET score = score + 1 WHERE id = %d`, i)))
	}
}

func requireBrokenAt(t *testing.T, q guard.Querier, seq int64) {
	t.Helper()
	st, err := guard.VerifyChain(context.Background(), q)
	require.NoError(t, err)
	require.Equal(t, guard.ChainStatus{BrokenAt: seq}, st)
}

func requireIntact(t *testing.T, q guard.Querier) {
	t.Helper()
	st, err := guard.VerifyChain(context.Background(), q)
	require.NoError(t, err)
	require.True(t, st.Intact, "broken at %d", st.BrokenAt)
}

func TestChainDetectsTamper(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		tamper string
		broken int64
	}{
		{"edit old values", `UPDATE basalt_meta.ledger SET old_row = jsonb_set(old_row, '{score}', '99') WHERE seq = 4`, 4},
		{"edit metadata", `UPDATE basalt_meta.ledger SET agent = 'someone' WHERE seq = 5`, 5},
		{"keep values but claim pruned", `UPDATE basalt_meta.ledger SET values_pruned = true WHERE seq = 6`, 6},
		{"delete a row", `DELETE FROM basalt_meta.ledger WHERE seq = 7`, 7},
		{"delete the tail", `DELETE FROM basalt_meta.ledger WHERE seq = 13`, 13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			a := d.NewAgent(t, "bot", leads, nil)
			writeSome(t, a, 6) // 1 + 6*2 = 13 rows
			requireIntact(t, a.Conn)
			d.Exec(t, `SET TimeZone = 'Asia/Jakarta'`)
			requireIntact(t, d.Admin)

			d.Exec(t, tc.tamper)
			requireBrokenAt(t, a.Conn, tc.broken)
		})
	}
}

func TestCheckHead(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	writeSome(t, a, 3)
	head, err := guard.Head(ctx, a.Conn)
	require.NoError(t, err)
	require.Equal(t, int64(7), head.Seq)
	require.Len(t, head.Hash, 32)

	ok, err := guard.CheckHead(ctx, a.Conn, head)
	require.NoError(t, err)
	require.True(t, ok)
	writeSome(t, a, 1)
	ok, err = guard.CheckHead(ctx, a.Conn, head)
	require.NoError(t, err)
	require.True(t, ok, "a longer chain still contains the old head")

	// A superuser rewrites seq 3 and re-hashes the tail consistently.
	d.Exec(t, `DO $$
	DECLARE prev bytea; l basalt_meta.ledger;
	BEGIN
		UPDATE basalt_meta.ledger SET detail = '{"forged": true}' WHERE seq = 3;
		SELECT hash INTO prev FROM basalt_meta.ledger WHERE seq = 2;
		FOR l IN SELECT * FROM basalt_meta.ledger WHERE seq >= 3 ORDER BY seq LOOP
			UPDATE basalt_meta.ledger SET prev_hash = prev, hash = sha256(prev || basalt_meta._canonical(l))
			 WHERE seq = l.seq RETURNING hash INTO prev;
		END LOOP;
		UPDATE basalt_meta.chain_head SET hash = prev WHERE id;
	END $$`)
	requireIntact(t, a.Conn)
	ok, err = guard.CheckHead(ctx, a.Conn, head)
	require.NoError(t, err)
	require.False(t, ok, "a rewritten history fails the pinned head")

	ok, err = guard.CheckHead(ctx, a.Conn, guard.ChainHead{Seq: 999, Hash: head.Hash})
	require.NoError(t, err)
	require.False(t, ok, "a head beyond the chain means rows were removed")
}

func TestAgentCannotForgeLedger(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	writeSome(t, a, 1)

	denied := []string{
		`INSERT INTO basalt_meta.ledger (seq, at, agent, kind, values_hash, prev_hash, hash) VALUES (99, now(), 'x', 'ROW_CHANGE', '\x', '\x', '\x')`,
		`UPDATE basalt_meta.ledger SET detail = '{}'`,
		`DELETE FROM basalt_meta.ledger`,
		`SELECT * FROM basalt_meta.ledger`,
		`UPDATE basalt_meta.changes SET status = 'APPLIED'`,
		`INSERT INTO basalt_meta.runs (run_id, agent, intent) VALUES (gen_random_uuid(), 'x', 'x')`,
		`UPDATE basalt_meta.chain_head SET seq = 0`,
		`SELECT basalt_meta._append('x', NULL, 'ROW_CHANGE', NULL, NULL, NULL, NULL, NULL, NULL, NULL)`,
		`SELECT basalt_meta._prune(now() + interval '10 years')`,
		`SELECT basalt_meta.attach('public.payroll', 'AGENT_WRITABLE')`,
		`ALTER TABLE public.leads DISABLE TRIGGER basalt_guard`,
		`DROP TRIGGER basalt_guard ON public.leads`,
		`SET session_replication_role = replica`,
		`DROP SCHEMA basalt_meta CASCADE`,
		`CREATE TABLE public.agent_made (id int)`,
		`SELECT * FROM public.payroll`,
		`SELECT * FROM public.lead_notes`,
	}
	for _, sql := range denied {
		_, err := a.Conn.Exec(ctx, sql)
		require.Error(t, err, sql)
		require.Equal(t, "42501", guardtest.SQLState(err), "%s: %v", sql, err)
	}

	_, err := a.Conn.Exec(ctx, `SELECT basalt_meta.record_event('ROW_CHANGE', NULL, '{}')`)
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	err = guard.Heartbeat(ctx, a.Conn, map[string]any{"pad": strings.Repeat("x", 70*1024)})
	requireCode(t, err, guard.CodeLedgerInputInvalid)
	requireIntact(t, a.Conn)
}
