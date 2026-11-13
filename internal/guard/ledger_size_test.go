package guard_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

const rowsForSizeGrowth = 10

func TestLedgerBytesAsTheAgent(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, nil)
	ctx := context.Background()

	before, err := guard.LedgerBytes(ctx, a.Conn)
	require.NoError(t, err)
	require.Positive(t, before)

	writeSome(t, a, rowsForSizeGrowth)
	after, err := guard.LedgerBytes(ctx, a.Conn)
	require.NoError(t, err)
	require.GreaterOrEqual(t, after, before)
}
