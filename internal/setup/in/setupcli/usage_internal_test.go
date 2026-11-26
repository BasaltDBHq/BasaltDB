package setupcli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The setup service's usage errors are the CLI's usage errors (exit 2),
// with their text unchanged; any other error stays as it is.
func TestServiceUsageErrorsAreTheCLIs(t *testing.T) {
	t.Parallel()
	err := cliUsage(fmt.Errorf("%w: this engine serves more than one agent: give --agent NAME", setup.ErrUsage))
	require.ErrorIs(t, err, cli.ErrUsage)
	require.ErrorIs(t, err, setup.ErrUsage)
	require.Equal(t, "usage: this engine serves more than one agent: give --agent NAME", err.Error())
	other := errors.New("the database could not be reached")
	require.Equal(t, other, cliUsage(other))
	require.NoError(t, cliUsage(nil))
}
