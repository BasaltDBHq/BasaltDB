package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func TestPruneKeepsChainVerifiable(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()
	writeSome(t, a, 3) // seq 1..7, three ROW_CHANGE rows with values

	// 31 days later: values are nulled, metadata kept, chain intact.
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '31 days')`)
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger WHERE old_row IS NOT NULL OR new_row IS NOT NULL`))
	require.Equal(t, 3, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger WHERE values_pruned`))
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.changes WHERE params IS NOT NULL`))
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger WHERE kind = 'PRUNED'`))
	requireIntact(t, a.Conn)

	// A year later: the oldest rows go, the anchor moves, the chain verifies
	// and new writes chain on.
	head, err := guard.Head(ctx, a.Conn)
	require.NoError(t, err)
	d.Exec(t, `SELECT basalt_meta._prune(now() + interval '366 days')`)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger`), "only the new PRUNED row")
	require.Equal(t, int(head.Seq), count(t, d.Admin, `SELECT seq::int FROM basalt_meta.chain_anchor`))
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.changes`))
	requireIntact(t, a.Conn)
	ok, err := guard.CheckHead(ctx, a.Conn, head)
	require.NoError(t, err)
	require.True(t, ok, "the anchor still proves the pinned head")

	writeSome(t, a, 1)
	requireIntact(t, a.Conn)
}

func TestPruneByAgent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	writeSome(t, a, 2)
	res, err := guard.Prune(context.Background(), a.Conn)
	require.NoError(t, err)
	require.Equal(t, guard.PruneResult{}, res)
	require.Zero(t, count(t, d.Admin, `SELECT count(1)::int FROM basalt_meta.ledger WHERE kind = 'PRUNED'`))
}
