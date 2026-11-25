package agentcatalog_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
)

// TestFieldRefReadsBack: a field ref the adapter writes reads back as the
// same column, and a ref it did not write is refused, never guessed.
func TestFieldRefReadsBack(t *testing.T) {
	t.Parallel()
	ref := agentcatalog.FieldRef(16384, 3)
	require.Equal(t, agentstore.FieldRef("16384/3"), ref)
	col, err := agentcatalog.ParseFieldRef(ref)
	require.NoError(t, err)
	require.Equal(t, pgcatalog.ColumnKey{OID: 16384, Attnum: 3}, col)

	for _, bad := range []agentstore.FieldRef{"", "16384", "16384/", "x/3", "16384/x", "16384/03", "016384/3", "16384/3/1", "16384/40000"} {
		_, err := agentcatalog.ParseFieldRef(bad)
		require.Error(t, err, "%q", bad)
	}
}
