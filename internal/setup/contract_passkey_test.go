package setup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// readsOnly is a transaction that answers the passkey lookup and refuses
// any write: the passkey rule only reads.
type readsOnly struct{ lookup error }

func (r readsOnly) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("a write")
}

func (r readsOnly) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("a query")
}

func (r readsOnly) QueryRow(context.Context, string, ...any) pgx.Row { return row{r.lookup} }

type row struct{ err error }

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = true //nolint:forcetypeassert // the lookup scans one bool
	return nil
}

// The passkey rule refuses PASSKEY_REQUIRED from a read alone, so Run can
// apply it before the setup's script: on a fresh database (no passkeys
// table), and with AddPasskey; a database with a passkey passes.
func TestRequirePasskeyOnlyReads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var e *setup.SetuprunRefusalError
	c := setup.NewContract(setupstore.New())
	fresh := pgquerier.Neutralize(readsOnly{lookup: &pgconn.PgError{Code: "42P01"}})
	has := pgquerier.Neutralize(readsOnly{})
	require.True(t, errors.As(setup.ContractRequirePasskey(c, ctx, fresh, false), &e))
	require.Equal(t, setup.SetuprunCodePasskeyRequired, e.Code)
	require.True(t, errors.As(setup.ContractRequirePasskey(c, ctx, has, true), &e))
	require.Equal(t, setup.SetuprunCodePasskeyRequired, e.Code)
	require.NoError(t, setup.ContractRequirePasskey(c, ctx, has, false))
}
