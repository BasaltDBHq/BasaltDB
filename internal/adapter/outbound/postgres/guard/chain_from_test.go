package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// rehashFrom3 rewrites the detail of row 3 and re-hashes the tail so the
// full check passes: a consistent rewrite of history.
const rehashFrom3 = `DO $$
DECLARE prev bytea; l basalt_meta.ledger;
BEGIN
	UPDATE basalt_meta.ledger SET detail = '{"forged": true}' WHERE seq = 3;
	SELECT hash INTO prev FROM basalt_meta.ledger WHERE seq = 2;
	FOR l IN SELECT * FROM basalt_meta.ledger WHERE seq >= 3 ORDER BY seq LOOP
		UPDATE basalt_meta.ledger SET prev_hash = prev, hash = sha256(prev || basalt_meta._canonical(l))
		 WHERE seq = l.seq RETURNING hash INTO prev;
	END LOOP;
	UPDATE basalt_meta.chain_head SET hash = prev WHERE id;
END $$`

func verifyFrom(t *testing.T, q guard.Querier, from guard.ChainHead) (guard.ChainStatus, guard.ChainHead) {
	t.Helper()
	st, head, err := guard.VerifyChainFrom(context.Background(), q, from)
	require.NoError(t, err)
	return st, head
}

func hashAt(t *testing.T, d *guardtest.DB, seq int64) []byte {
	t.Helper()
	var h []byte
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT hash FROM basalt_meta.ledger WHERE seq = $1`, seq).Scan(&h))
	return h
}

func TestVerifyChainFromPinsAndExtends(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	writeSome(t, a, 3) // seq 1..7

	st, head := verifyFrom(t, a.Conn, guard.Genesis())
	require.True(t, st.Intact)
	want, err := guardtest.Head(ctx, a.Conn)
	require.NoError(t, err)
	require.Equal(t, want, head, "the full check from genesis returns the head")

	writeSome(t, a, 2) // seq 8..12
	st, next := verifyFrom(t, a.Conn, head)
	require.True(t, st.Intact)
	require.Equal(t, int64(12), next.Seq)

	st, same := verifyFrom(t, a.Conn, next)
	require.True(t, st.Intact, "nothing new to check")
	require.Equal(t, next, same)
}

func TestVerifyChainFromDetectsTamper(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		tamper string
		pin    int64
		broken int64
	}{
		{"edit a row after the pin", `UPDATE basalt_meta.ledger SET agent = 'someone' WHERE seq = 6`, 4, 6},
		{"edit the pinned row", `UPDATE basalt_meta.ledger SET detail = '{}' WHERE seq = 4`, 4, 4},
		{"rewrite history before the pin", rehashFrom3, 5, 5},
		{"cut the tail and move the head", `DELETE FROM basalt_meta.ledger WHERE seq >= 6;
			UPDATE basalt_meta.chain_head SET seq = 5, hash = (SELECT hash FROM basalt_meta.ledger WHERE seq = 5)`, 7, 6},
		{"remove a row after the pin", `DELETE FROM basalt_meta.ledger WHERE seq = 6`, 4, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			a := d.NewAgent(t, "bot", leads, nil)
			writeSome(t, a, 3) // seq 1..7
			pin := guard.ChainHead{Seq: tc.pin, Hash: hashAt(t, d, tc.pin)}

			d.Exec(t, tc.tamper)
			st, back := verifyFrom(t, a.Conn, pin)
			require.Equal(t, guard.ChainStatus{BrokenAt: tc.broken}, st)
			require.Equal(t, pin, back, "a broken chain keeps the old pin")
		})
	}
}

func TestVerifyChainFromAfterRetention(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	writeSome(t, a, 2) // seq 1..5
	early := guard.ChainHead{Seq: 3, Hash: hashAt(t, d, 3)}
	head, err := guardtest.Head(ctx, a.Conn)
	require.NoError(t, err)

	// A year later retention deletes every row; the anchor is the old head.
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	st, _ := verifyFrom(t, a.Conn, early)
	require.True(t, st.Intact, "a pin older than the anchor verifies from the anchor")
	st, _ = verifyFrom(t, a.Conn, head)
	require.True(t, st.Intact, "the anchor proves the pinned head")
	st, _ = verifyFrom(t, a.Conn, guard.ChainHead{Seq: head.Seq, Hash: early.Hash})
	require.Equal(t, guard.ChainStatus{BrokenAt: head.Seq}, st, "the anchor disagrees with the pin")
	requireIntact(t, a.Conn)
}

func TestVerifyChainFromRefusesBadInput(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	_, _, err := guard.VerifyChainFrom(context.Background(), a.Conn, guard.ChainHead{Seq: -1, Hash: []byte{1}})
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	st, _ := verifyFrom(t, a.Conn, guard.ChainHead{Seq: 99, Hash: []byte{1}})
	require.Equal(t, guard.ChainStatus{BrokenAt: 1}, st, "a pin beyond the head means rows were removed")
}

func TestRecordEventKinds(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	for _, k := range []guard.EventKind{guard.EventHeartbeat, guard.EventDeadMan, guard.EventUncoveredTables} {
		require.NoError(t, guard.RecordEvent(ctx, a.Conn, k, map[string]any{"k": string(k)}))
	}
	require.Equal(t, 3, count(t, d.Admin,
		`SELECT count(1)::int FROM basalt_meta.ledger WHERE kind IN ('HEARTBEAT', 'DEAD_MAN', 'UNCOVERED_TABLES')`))
	err := guard.RecordEvent(ctx, a.Conn, "RUN_STARTED", nil)
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	requireIntact(t, a.Conn)
}
