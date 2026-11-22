package budget

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBudgetIsSharedByTheCallAndStopsPastItsMax(t *testing.T) {
	t.Parallel()
	ctx := WithMax(context.Background(), 100)
	b := From(ctx)
	require.NoError(t, b.Charge(60))
	require.Same(t, b, From(Ensure(ctx)), "Ensure keeps the call's budget")
	require.ErrorIs(t, b.Charge(41), ErrSizeLimit, "both charges count against one budget")

	require.Nil(t, From(context.Background()), "no budget: the person's reads")
	require.NoError(t, From(context.Background()).Charge(MaxBytes*2), "a nil budget charges nothing")
	require.Equal(t, int64(MaxBytes), From(With(context.Background())).Max())
	require.Nil(t, From(Without(ctx)))
}
