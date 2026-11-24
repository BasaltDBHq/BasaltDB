package sqllang

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

// TestParseResourceErrors pins the texts describe puts after "invalid
// arguments: resource ".
func TestParseResourceErrors(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"orders":        "must be schema.table, with the schema",
		"a.b.c":         "must be schema.table, with the schema",
		`"shop.orders`:  "has an unclosed quote",
		`"".t`:          "has an empty quoted name",
		"a b.t":         "must be schema.table, each part a name or a double-quoted name",
		`"a"x.t`:        "must be schema.table",
		"":              "must be schema.table, each part a name or a double-quoted name",
		"shop.":         "must be schema.table, each part a name or a double-quoted name",
		`"shop"."ord"x`: "must be schema.table",
	} {
		_, _, err := Language{}.ParseName(in)
		require.EqualError(t, err, want, in)
	}
}

// TestPrintName quotes exactly where Postgres's quote_ident does.
func TestPrintName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ schema, name, want string }{
		{"public", "orders", "public.orders"},
		{"Sales", "Order Items", `"Sales"."Order Items"`},
		{"public", `a"b`, `public."a""b"`},
		{"public", "select", `public."select"`},
		{"public", "name", "public.name"}, // unreserved keyword stays bare
		{"public", "t1$", "public.t1$"},
		{"public", "1t", `public."1t"`},
		{"public", "$t", `public."$t"`},
		{"", "t", `"".t`},
		{"public", "café", `public."café"`},
	} {
		require.Equal(t, tc.want, Language{}.PrintName(tc.schema, tc.name))
	}
}
