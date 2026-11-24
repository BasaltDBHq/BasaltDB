package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseResource: an unquoted name folds to lower case as Postgres folds
// it, ASCII A to Z only; a quoted one is kept as written.
func TestParseResource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, schema, name string }{
		{"shop.orders", "shop", "orders"},
		{"Shop.ORDERS", "shop", "orders"},
		{`"Sales"."Order Items"`, "Sales", "Order Items"},
		{`"a""b".t`, `a"b`, "t"},
		{"Café.Ärger", "café", "Ärger"}, // non-ASCII letters keep their case
	} {
		schema, name, err := parseResource(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, []string{tc.schema, tc.name}, []string{schema, name}, tc.in)
	}
	for _, bad := range []string{"orders", `"shop.orders`, `"".t`, "a b.t", "a.b.c"} {
		_, _, err := parseResource(bad)
		require.Error(t, err, bad)
	}
}
