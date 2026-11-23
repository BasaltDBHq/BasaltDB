package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServiceRunsParse(t *testing.T) {
	t.Parallel()
	runs, last, err := parseLaunchdRuns("system/dev.basaltdb.engine = {\n\tactive count = 0\n\tstate = spawn scheduled\n\truns = 4\n\tlast exit code = 1\n}\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{4, 1}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 2\n\tlast exit code = 78: EX_CONFIG\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{2, 78}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 3\n\tlast exit code = 1: Operation not permitted\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{3, 1}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 1\n\tlast exit code = (never exited)\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{1, -1}, [2]int{runs, last})
	_, _, err = parseLaunchdRuns("Bad request.\n")
	require.Error(t, err)

	runs, last, err = parseSystemdRuns("NRestarts=3\nExecMainStatus=1\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{4, 1}, [2]int{runs, last})
	_, _, err = parseSystemdRuns("")
	require.Error(t, err)
}
