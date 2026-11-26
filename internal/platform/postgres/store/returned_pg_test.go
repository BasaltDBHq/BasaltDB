package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// ignoreReturned is a store-only test's Returned: no agent gets the rows.
func ignoreReturned(context.Context, sqlport.Port, []action.Column, []map[string]any) error {
	return nil
}

// A write that returns rows with no Returned to hand them to is refused
// before COMMIT: nothing is applied. One that returns none needs none.
func TestWriteRefusesReturnedRowsWithNoReturned(t *testing.T) {
	t.Parallel()
	d, a := zoneDB(t)
	ctx := context.Background()
	store := postgres.NewStore(zonedPool(t, a.URL, "UTC"), sqlguard.DefaultLimits(), time.Now)
	in := action.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Tag events"}
	require.NoError(t, store.StartRun(ctx, in))

	_, err := store.Write(ctx, in, action.OpUpdate, `UPDATE public.events SET note = 'seen' WHERE id = 1 RETURNING note`, nil, nil)
	require.Error(t, err)
	var note string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT note FROM public.events WHERE id = 1`).Scan(&note))
	require.Equal(t, "note 1", note, "the write was rolled back")

	res, err := store.Write(ctx, in, action.OpUpdate, `UPDATE public.events SET note = 'seen' WHERE id = 2`, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, res.Rows)
}
