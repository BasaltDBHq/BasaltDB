package ledger

import (
	"encoding/base64"
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// A cursor whose id is not a UUID is refused before any SQL, as a stale
// cursor, rather than reaching Postgres as a bad uuid value.
func TestApplyIDKeysetRefusesANonUUIDCursor(t *testing.T) {
	t.Parallel()
	b := sq.Select("change_id").From("changes")
	for _, c := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"id":"x"}`)),
	} {
		_, err := applyIDKeyset(b, "change_id", true, c)
		require.ErrorIs(t, err, pagination.ErrStaleCursor, c)
	}
}

func TestApplyIDKeysetBindsTheParsedID(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	b, err := applyIDKeyset(sq.Select("change_id").From("changes"), "change_id", true, pagination.EncodeIDCursor(id.String()))
	require.NoError(t, err)
	sql, args, err := b.ToSql()
	require.NoError(t, err)
	require.Contains(t, sql, "change_id < ?")
	require.Equal(t, []any{id.String()}, args)
}
