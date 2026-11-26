package setup

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Check's and RevokePasskey's passkey lists keep the service's nil and
// empty apart: nil is a database without the guard (or none left), empty
// is the guard with no active passkey. Each passkey keeps its fields, with
// its own copy of the credential id.
func TestActivePasskeysKeepNilAndEmptyApart(t *testing.T) {
	t.Parallel()
	require.Nil(t, activePasskeys(nil))
	empty := activePasskeys([]guardmodel.RegisteredPasskey{})
	require.NotNil(t, empty)
	require.Empty(t, empty)

	at, used := time.Unix(1700000000, 0).UTC(), time.Unix(1700000600, 0).UTC()
	id := []byte{1, 2, 3}
	got := activePasskeys([]guardmodel.RegisteredPasskey{{ID: id, Label: "laptop", RPID: PortalRPID, CreatedAt: at, LastUsedAt: &used}})
	require.Equal(t, []ActivePasskey{{CredentialID: []byte{1, 2, 3}, Label: "laptop", RPID: PortalRPID, CreatedAt: at, LastUsedAt: &used}}, got)
	id[0] = 9
	require.Equal(t, byte(1), got[0].CredentialID[0], "the credential id is a copy")
}
