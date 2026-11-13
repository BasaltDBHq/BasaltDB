package guardtest_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func TestDatabasesPrintTimestampsInUTC(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	var zone string
	require.NoError(t, d.Admin.QueryRow(context.Background(), "SHOW TimeZone").Scan(&zone))
	require.Equal(t, "UTC", zone, "whatever the server's own TimeZone is")
}
