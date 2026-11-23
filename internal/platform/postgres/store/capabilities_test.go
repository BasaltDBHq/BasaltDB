package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// The capability values are the contract's (CONTRACT.md, Stores,
// Capabilities), which the engine may rely on.
func TestPostgresCapabilities(t *testing.T) {
	t.Parallel()
	s := store.NewStore(nopDB{}, sqlguard.DefaultLimits(), time.Now)
	require.Equal(t, action.StorePostgres, s.Kind())
	require.Equal(t, action.Capabilities{
		InStoreEnforcement:    true,
		InStoreLedger:         true,
		InStoreSignatureCheck: true,
		TransactionalPreview:  true,
		ConditionalWrites:     true,
		TargetConflicts:       action.TargetRow,
		Cascades:              true,
		RetainsHistory:        false,
	}, s.Capabilities())
}

// nopDB is a DB the test never queries.
type nopDB struct{ store.DB }
