package setup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// listsPasskeys is a contract backend whose database has the passkeys
// table or not, with no active passkey.
type listsPasskeys struct {
	ContractBackend
	installed bool
}

func (l listsPasskeys) PasskeysInstalled(context.Context, Querier) (bool, error) {
	return l.installed, nil
}

func (listsPasskeys) ActivePasskeys(context.Context, Querier) ([]guardmodel.RegisteredPasskey, error) {
	return nil, nil
}

// Check's passkey list tells a database without the guard (nil) from one
// with the guard and no active passkey (empty, not nil).
func TestContractPasskeysTellNoGuardFromNone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	none, err := NewContract(listsPasskeys{}).activePasskeys(ctx, nil)
	require.NoError(t, err)
	require.Nil(t, none)
	empty, err := NewContract(listsPasskeys{installed: true}).activePasskeys(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, empty)
	require.Empty(t, empty)
}
