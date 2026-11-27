package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// argsQuerier records the arguments of the one row it is asked for and
// answers it with no time: the request no longer waited.
type argsQuerier struct{ args *[]any }

func (q argsQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (q argsQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("argsQuerier answers one row only")
}

func (q argsQuerier) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	*q.args = args
	return nullRow{}
}

// nullRow scans SQL NULL into its one destination.
type nullRow struct{}

func (nullRow) Scan(dest ...any) error { return nil }

// A reason with a NUL reaches Postgres with U+FFFD in its place: text
// cannot hold a NUL, and the withdrawal must still record.
func TestWithdrawSendsNoNUL(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	for name, call := range map[string]func(Querier) error{
		"approval": func(q Querier) error {
			_, err := WithdrawApproval(context.Background(), q, id, "wrong\x00rows")
			return err
		},
		"revert": func(q Querier) error {
			_, err := WithdrawRevert(context.Background(), q, id, "wrong\x00rows")
			return err
		},
		"plugin": func(q Querier) error {
			_, err := WithdrawPluginApproval(context.Background(), q, id, "wrong\x00rows")
			return err
		},
	} {
		var args []any
		require.NoError(t, call(argsQuerier{args: &args}), name)
		require.Equal(t, []any{id.String(), "wrong�rows"}, args, name)
	}
}
