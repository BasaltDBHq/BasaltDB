package pgstatement

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// The walker collects every function a statement calls, as written and
// wherever it is called: the function allowlist checks this list.
func TestWalkerCollectsFunctions(t *testing.T) {
	t.Parallel()
	for sql, want := range map[string][]string{
		"SELECT id FROM leads WHERE id IN (SELECT id FROM notes WHERE lower(body) = 'x')": {"lower"},
		"SELECT * FROM generate_series(1, 3) AS g(n)":                                     {"generate_series"},
		"SELECT now()":                 {"now"},
		"SELECT count(*) FROM leads":   {"count"},
		"SELECT pg_catalog.lower('A')": {"pg_catalog.lower"},
		"SELECT 1":                     {},
	} {
		_, node, err := parseOne(sql)
		require.NoError(t, err, sql)
		w := &walker{tables: map[string]bool{}, funcs: map[string]bool{}, ctes: map[string]bool{}}
		w.visit(node.ProtoReflect())
		require.Equal(t, want, append([]string{}, slices.Sorted(maps.Keys(w.funcs))...), sql)
	}
}
