package guard

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// nameParts splits the names the SQL check gives (folded, unquoted) into
// schema and relation; a name it cannot split keeps neither, so the guard
// records it as written.
func TestNameParts(t *testing.T) {
	t.Parallel()
	written, schemas, rels := nameParts([]string{"leads", "public.leads", "Old Leads", "a.b.c", ".x", ""})
	require.Equal(t, []string{"leads", "public.leads", "Old Leads", "a.b.c", ".x", ""}, written)
	require.Equal(t, []string{"", "public", "", "", "", ""}, schemas)
	require.Equal(t, []string{"leads", "leads", "Old Leads", "", "", ""}, rels)

	written, schemas, rels = nameParts(nil)
	require.Equal(t, []string{}, written, "an empty array, never NULL")
	require.Equal(t, []string{}, schemas)
	require.Equal(t, []string{}, rels)
}
