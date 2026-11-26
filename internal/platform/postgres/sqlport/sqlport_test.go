package sqlport_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// The timeout is set for the transaction only, through the qualified
// set_config, in whole milliseconds.
func TestStatementTimeoutSQL(t *testing.T) {
	t.Parallel()
	sql, args, err := sqlport.StatementTimeoutSQL(5*time.Second + 400*time.Microsecond)
	require.NoError(t, err)
	require.Equal(t, "SELECT pg_catalog.set_config('statement_timeout', $1, true)", sql)
	require.Equal(t, []any{"5000"}, args)
}
