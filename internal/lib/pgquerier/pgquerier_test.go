package pgquerier_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
)

// txOnly is a handle with no BeginTx, as a transaction is.
type txOnly struct{ pgquerier.Querier }

// A handle that cannot begin a transaction of its own has no snapshots.
func TestReadOnlySnapshotOfATransaction(t *testing.T) {
	run, ok := pgquerier.Neutralize(txOnly{}).ReadOnlySnapshot()
	require.False(t, ok)
	require.Nil(t, run)
}
