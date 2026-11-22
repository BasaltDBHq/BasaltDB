package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// The mappers keep a nil list nil and an empty one empty, so a body the
// service marshals says null or [] exactly as the guard's value did.
func TestMappersKeepNilAndEmptyApart(t *testing.T) {
	t.Parallel()
	require.Nil(t, previewPageOf(action.PreviewPage{}).Page)
	require.NotNil(t, previewPageOf(action.PreviewPage{Page: []action.PreviewLine{}}).Page)
	require.Nil(t, batchResultOf(action.BatchResult{}).Items)
	require.NotNil(t, batchResultOf(action.BatchResult{Items: []action.BatchItem{}}).Items)
	require.Nil(t, catalogOf(nil))
	c := catalogOf(&action.RevertCatalog{Agents: []action.CatalogAgent{}})
	require.NotNil(t, c.Agents)
	require.Nil(t, c.Runs)
	require.Nil(t, c.Tables)
}
