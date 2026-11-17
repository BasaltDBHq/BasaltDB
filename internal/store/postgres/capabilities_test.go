package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/store/postgres"
)

// The capability values are the contract's (CONTRACT.md, Stores,
// Capabilities), which the engine may rely on.
func TestPostgresCapabilities(t *testing.T) {
	t.Parallel()
	s := postgres.NewStore(nopDB{}, sqlguard.DefaultLimits(), time.Now)
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
type nopDB struct{ postgres.DB }
