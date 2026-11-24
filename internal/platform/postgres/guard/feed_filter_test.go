package guard_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// captureQuery keeps the SQL of the query it is asked to run.
type captureQuery struct{ sql string }

var errCaptured = errors.New("captured")

func (c *captureQuery) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errCaptured
}

func (c *captureQuery) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	c.sql = sql
	return nil, errCaptured
}

func (c *captureQuery) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

// A feed filter with no Include flags reads no unapplied CHANGE and no
// refused SELECT; each flag drops its clause.
func TestReadFeedRowsFilterFlags(t *testing.T) {
	const applied = "detail ->> 'status' = 'APPLIED'"
	const notSelect = "op IS DISTINCT FROM 'SELECT'"
	for _, c := range []struct {
		f                    guardmodel.FeedFilter
		applied, notSelected bool
	}{
		{guardmodel.FeedFilter{Kinds: []string{guardmodel.KindChange}}, true, true},
		{guardmodel.FeedFilter{Kinds: []string{guardmodel.KindChange}, IncludeUnappliedChanges: true}, false, true},
		{guardmodel.FeedFilter{Kinds: []string{guardmodel.KindChange}, IncludeRefusedReads: true}, true, false},
	} {
		q := &captureQuery{}
		_, err := guard.ReadFeedRows(context.Background(), q, 0, 10, c.f)
		require.ErrorIs(t, err, errCaptured)
		require.Equal(t, c.applied, strings.Contains(q.sql, applied), "%+v: %s", c.f, q.sql)
		require.Equal(t, c.notSelected, strings.Contains(q.sql, notSelect), "%+v: %s", c.f, q.sql)
	}
}
