package sqlident_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/sqlident"
)

func TestQuote(t *testing.T) {
	cases := []struct {
		parts []string
		want  string
	}{
		{nil, ``},
		{[]string{""}, `""`},
		{[]string{"orders"}, `"orders"`},
		{[]string{"public", "orders"}, `"public"."orders"`},
		{[]string{`we"ird`}, `"we""ird"`},
		{[]string{`""`}, `""""""`},
		{[]string{"a.b"}, `"a.b"`},
		{[]string{"nul\x00name"}, `"nulname"`},
		{[]string{"\x00\"\x00"}, `""""`},
		{[]string{"Ünïcode", "Mixed Case"}, `"Ünïcode"."Mixed Case"`},
		{[]string{"db", "schema", "ta ble"}, `"db"."schema"."ta ble"`},
	}
	for _, c := range cases {
		got := sqlident.Quote(c.parts...)
		require.Equal(t, c.want, got, "Quote(%q)", c.parts)
		// The engine quoted with pgx before; the SQL it builds must not change.
		require.Equal(t, pgx.Identifier(c.parts).Sanitize(), got, "Quote(%q) differs from pgx", c.parts)
	}
}
