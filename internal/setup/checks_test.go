package setup

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Saved init arguments never carry a password or a connection string with
// user info: init and service install refuse them before engine.json is
// written.
func TestRefuseSecretInitArgs(t *testing.T) {
	t.Parallel()
	require.NoError(t, RefuseSecretInitArgs([]string{"--agent=bot", "--write=public.leads", "--passkey-origin=https://portal.basaltvault.app"}))
	for _, bad := range [][]string{
		{"--database-url=postgres://admin:" + "pw@db/app"}, // split so no literal credential sits in the source
		{"--x", "postgres://admin@db/app"},
		{"--y=host=db password=pw"},
		{"--Z=PASSWORD=pw"},
	} {
		require.Error(t, RefuseSecretInitArgs(bad), "%v", bad)
	}
}
