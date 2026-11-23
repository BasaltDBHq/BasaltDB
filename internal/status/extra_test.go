package status

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusAccessListsAreEmptyNotNullAndBounded(t *testing.T) {
	t.Parallel()
	many := make([]string, maxAccessTables+5)
	for i := range many {
		many[i] = "public.t"
	}
	svc := newService(func(_ *Core, d *Deps) {
		d.Access = func(context.Context) (CatalogAccess, error) { return CatalogAccess{Read: many}, nil }
	})
	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	require.Len(t, r.Access.Read, maxAccessTables)
	require.Equal(t, []string{}, r.Access.Write)
	require.True(t, r.Access.Truncated)
	require.Contains(t, string(raw), `"write":[]`)
}
