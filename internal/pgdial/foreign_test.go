package pgdial_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// CheckForeignDSN takes only a URL pgx reads no file for. The full table of
// refusals runs through its callers (cmd/basalt and internal/engine).
func TestCheckForeignDSN(t *testing.T) {
	t.Parallel()
	require.NoError(t, pgdial.CheckForeignDSN("postgres://u:pw@db.example.com/app?sslmode=require&default_query_exec_mode=exec"))
	for _, dsn := range []string{
		"postgres://u:pw@db.example.com/app?sslcert=/root/c",
		"postgres://u@db.example.com/app",
		"host=db.example.com password=pw",
		"postgres://u:pw@db.example.com,other.example.com/app",
	} {
		require.ErrorIs(t, pgdial.CheckForeignDSN(dsn), pgdial.ErrForeignDSN, dsn)
	}
	require.Contains(t, pgdial.ErrForeignDSN.Error(), "application_name, channel_binding")
}
