package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The mappers keep a nil list nil and an empty one empty, so a body the
// service marshals says null or [] exactly as the guard's value did.
func TestMappersKeepNilAndEmptyApart(t *testing.T) {
	t.Parallel()
	require.Nil(t, previewPageOf(guardmodel.PreviewPage{}).Page)
	require.NotNil(t, previewPageOf(guardmodel.PreviewPage{Page: []guardmodel.PreviewLine{}}).Page)
	require.Nil(t, batchResultOf(guardmodel.BatchResult{}).Items)
	require.NotNil(t, batchResultOf(guardmodel.BatchResult{Items: []guardmodel.BatchItem{}}).Items)
	require.Nil(t, catalogOf(nil))
	c := catalogOf(&guardmodel.RevertCatalog{Agents: []guardmodel.CatalogAgent{}})
	require.NotNil(t, c.Agents)
	require.Nil(t, c.Runs)
	require.Nil(t, c.Tables)
}
