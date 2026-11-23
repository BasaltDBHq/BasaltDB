package setup_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

func TestCheckBuildVersion(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"0.0.1", "0.0.1-alpha.2", "0.0.1-alpha.1-295-gced6c31", "1.2.3"} {
		require.NoError(t, setup.CheckBuildVersion(ok), ok)
	}
	for _, bad := range []string{"dev", "master-ced6c31", "", "0.0"} {
		err := setup.CheckBuildVersion(bad)
		require.Error(t, err, bad)
		require.NotErrorIs(t, err, cli.ErrUsage)
		require.Contains(t, err.Error(), "install a release build")
	}
}
