package resultsize

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"
)

func TestRowCostChargesEveryValueItsNameAndItsEscapes(t *testing.T) {
	t.Parallel()
	fds := []pgconn.FieldDescription{{Name: "id"}, {Name: "body"}}
	require.Equal(t, 2*valueOverhead+len("id")+len("body"), RowCost(fds, [][]byte{nil, nil}), "NULLs cost their overhead")
	require.Equal(t, 2*valueOverhead+6+3+(4+3*jsonEscapeCost), RowCost(fds, [][]byte{[]byte("123"), []byte(`<a">`)}))
}

func TestBudgetIsSharedByTheCallAndStopsPastItsMax(t *testing.T) {
	t.Parallel()
	ctx := budget.WithMax(context.Background(), 100)
	b := budget.From(ctx)
	require.NoError(t, b.Charge(60))
	require.Same(t, b, budget.From(budget.Ensure(ctx)), "Ensure keeps the call's budget")
	require.ErrorIs(t, b.Charge(41), budget.ErrSizeLimit, "both charges count against one budget")
	require.True(t, IsSizeLimit(b.Charge(1)))

	require.Nil(t, budget.From(context.Background()), "no budget: the person's reads")
	require.NoError(t, budget.From(context.Background()).Charge(budget.MaxBytes*2), "a nil budget charges nothing")
	require.NotNil(t, budget.From(budget.Ensure(context.Background())))
	require.Equal(t, int64(budget.MaxBytes), budget.From(budget.With(context.Background())).Max())
}
