package store

import (
	"encoding/base64"
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// list_runs refuses the same bad cursors as the ledger lists, with the
// same typed error.
func TestRunKeysetRefusesAStaleCursor(t *testing.T) {
	t.Parallel()
	b := sq.Select(runIDColumn).From("runs")
	for _, c := range []string{
		"%%%",
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"id":"x"}`)),
	} {
		_, err := runKeyset(b, true, c)
		require.ErrorIs(t, err, pagination.ErrStaleCursor, c)
	}
}
