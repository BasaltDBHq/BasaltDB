package setupstore_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The guard's Detail and Hint reach the refusal text, worded as before; an
// error with neither, or no database error, is left as it is.
func TestGuardDetail(t *testing.T) {
	t.Parallel()
	b := setupstore.New()
	pg := &pgconn.PgError{
		Severity: "ERROR", Code: "BS007", Message: "NOT_ALLOWED",
		Detail: "table crm.nopk has no primary key", Hint: "add a primary key, or revoke the agent's write",
	}
	err := setup.WithGuardDetail(b, fmt.Errorf("init step 3: %w", pg))
	require.Equal(t, "init step 3: ERROR: NOT_ALLOWED (SQLSTATE BS007): table crm.nopk has no primary key. add a primary key, or revoke the agent's write.", err.Error())
	require.ErrorIs(t, err, pg)
	require.Equal(t, err, setup.WithGuardDetail(b, err), "already carrying them")
	require.Equal(t, "init step 3: ERROR: NOT_ALLOWED (SQLSTATE BS007): table crm.nopk has no primary key. add a primary key, or revoke the agent's write. Nothing changed.",
		setup.NothingChanged(err).Error())

	bare := &pgconn.PgError{Severity: "ERROR", Code: "BS007", Message: "NOT_ALLOWED"}
	require.Same(t, error(bare), setup.WithGuardDetail(b, bare))
	plain := errors.New("connection reset")
	require.Same(t, plain, setup.WithGuardDetail(b, plain))
	require.NoError(t, setup.WithGuardDetail(b, nil))
}

func TestUndefinedTable(t *testing.T) {
	t.Parallel()
	b := setupstore.New()
	require.True(t, b.UndefinedTable(fmt.Errorf("read: %w", &pgconn.PgError{Code: "42P01"})))
	require.False(t, b.UndefinedTable(&pgconn.PgError{Code: "42501"}))
	require.False(t, b.UndefinedTable(errors.New("42P01")))
	require.False(t, b.UndefinedTable(nil))
}
