package pgcatalog_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
)

const testSchema = "pgcatalog_test"

func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	url := os.Getenv("BASALTDB_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("BASALTDB_TEST_POSTGRES_URL not set")
	}
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, url)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`)
		_ = conn.Close(context.Background())
	})
	// Plain SQL: test fixture DDL.
	_, err = conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE;
		CREATE SCHEMA `+testSchema+`;
		CREATE TABLE `+testSchema+`.leads (id int PRIMARY KEY, name text);
		CREATE TABLE `+testSchema+`.notes (
			lead_id int REFERENCES `+testSchema+`.leads (id) ON DELETE CASCADE,
			seq int,
			body text,
			PRIMARY KEY (lead_id, seq)
		);
		CREATE TABLE `+testSchema+`.log (body text);`)
	require.NoError(t, err)
	return conn
}

func TestPrimaryKey(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()

	pk, err := pgcatalog.PrimaryKey(ctx, conn, testSchema, "notes")
	require.NoError(t, err)
	require.Equal(t, []string{"lead_id", "seq"}, pk)

	pk, err = pgcatalog.PrimaryKey(ctx, conn, testSchema, "log")
	require.NoError(t, err)
	require.Empty(t, pk)
}
