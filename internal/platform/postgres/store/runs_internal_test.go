package store

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

func TestRunKeysetRefusesAStaleCursor(t *testing.T) {
	t.Parallel()
	for _, c := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"id":"x"}`)),
		pagination.EncodeIDCursor(uuid.Must(uuid.NewV7()).String()), // a cursor without a time
	} {
		_, _, err := runKeyset(action.RunListParams{Params: pagination.Params{Cursor: c}}, true)
		require.ErrorIs(t, err, pagination.ErrStaleCursor, c)
	}
}

// The cursor continues after the last item of the page, by the item's time,
// kind and id, in the direction of the sort.
func TestRunKeysetContinuesAfterTheLastItem(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 27, 9, 0, 0, 123456000, time.UTC)
	id := uuid.Must(uuid.NewV7())
	cursor := pagination.EncodeTimeCursor(at, action.RunItemRevert, id)
	end := at.Add(time.Hour)

	where, args, err := runKeyset(action.RunListParams{Params: pagination.Params{Cursor: cursor}, EndTime: &end}, true)
	require.NoError(t, err)
	require.Equal(t, "true AND ts < $1 AND (ts, kind, id) < ($2::timestamptz, $3::text, $4::uuid)", where)
	require.Equal(t, []any{end, at, action.RunItemRevert, id}, args)

	where, _, err = runKeyset(action.RunListParams{Params: pagination.Params{Cursor: cursor}}, false)
	require.NoError(t, err)
	require.Equal(t, "true AND (ts, kind, id) > ($1::timestamptz, $2::text, $3::uuid)", where)
}

func TestRunsWithoutAFilterOrCursorHaveNoKeyset(t *testing.T) {
	t.Parallel()
	where, args, err := runKeyset(action.RunListParams{}, true)
	require.NoError(t, err)
	require.Equal(t, "true", where)
	require.Empty(t, args)
}
