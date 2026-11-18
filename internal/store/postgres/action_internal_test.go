package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The mappers keep a nil list nil and an empty one empty, so a body the
// service marshals says null or [] exactly as the guard's value did.
func TestMappersKeepNilAndEmptyApart(t *testing.T) {
	t.Parallel()
	require.Nil(t, previewPageOf(guard.PreviewPage{}).Page)
	require.NotNil(t, previewPageOf(guard.PreviewPage{Page: []guard.PreviewLine{}}).Page)
	require.Nil(t, batchResultOf(guard.BatchResult{}).Items)
	require.NotNil(t, batchResultOf(guard.BatchResult{Items: []guard.BatchItem{}}).Items)
	require.Nil(t, catalogOf(nil))
	c := catalogOf(&guard.RevertCatalog{Agents: []guard.CatalogAgent{}})
	require.NotNil(t, c.Agents)
	require.Nil(t, c.Runs)
	require.Nil(t, c.Tables)
}
