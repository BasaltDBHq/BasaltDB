package guard

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
)

// TestDecodeRescopedReadsResources: rescope_revert's catalog lists
// resources (schema version 10); the decode keeps each as a catalog table,
// so the store-neutral answer never drops one.
func TestDecodeRescopedReadsResources(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("0b8f6c3e-6a1f-4d3a-9b8e-2f4c1d7a9e10")
	change := uuid.MustParse("0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a7b")
	raw := []byte(`{"revertId": "` + id.String() + `", "binding": "{}", "expiresAt": "2026-11-25T10:00:00.000001Z",
		"lines": [], "rescopeNonce": "AAEC", "scopeToken": "AwQF",
		"catalog": {"agents": [{"agent": "agent:bot", "changes": 2}], "runs": [],
			"resources": [{"resource": "public.leads", "rows": 3}],
			"changeAgents": {"` + change.String() + `": "agent:bot"}}}`)
	got, err := decodeRescoped(raw)
	require.NoError(t, err)
	require.Equal(t, id, got.RevertID)
	require.Equal(t, []byte{0, 1, 2}, []byte(got.RescopeNonce))
	require.Equal(t, []byte{3, 4, 5}, []byte(got.ScopeToken))
	require.Equal(t, &revertstore.RevertCatalog{
		Agents: []revertstore.CatalogAgent{{Agent: "agent:bot", Changes: 2}}, Runs: []revertstore.CatalogRun{},
		Tables:       []revertstore.CatalogTable{{Table: "public.leads", Rows: 3}},
		ChangeAgents: map[uuid.UUID]string{change: "agent:bot"},
	}, got.Catalog)

	got, err = decodeRescoped([]byte(`{"revertId": "` + id.String() + `", "binding": "{}", "lines": []}`))
	require.NoError(t, err)
	require.Nil(t, got.Catalog, "an own-work rescope has no catalog")
}
