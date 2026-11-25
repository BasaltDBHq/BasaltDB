package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// A result column from a table is its field ref; a computed one (oid 0)
// has none. The key is the column's name in each row.
func TestResultFieldsNameEachColumnsField(t *testing.T) {
	got := resultFields([]action.Column{
		{Name: "email", TableOID: 16384, Attnum: 3},
		{Name: "lower", TableOID: 0, Attnum: 0},
	})
	require.Equal(t, []piistore.ResultField{{Ref: "16384/3", Key: "email"}, {Key: "lower"}}, got)
	require.Empty(t, resultFields(nil))
}
