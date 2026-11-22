package app

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// A same-user engine reaps the plugin run records under its state
// directory before it records new ones; a service engine and an engine run
// as root start no local plugin process, so they record nothing.
// TestPluginRunsUnlessRoot: an engine records and reaps the local plugin
// processes it starts, in same-user mode and, for its approved engine-kept
// entries, in service mode; an engine running as root starts none.
func TestPluginRunsUnlessRoot(t *testing.T) {
	t.Parallel()
	discard := slog.New(slog.DiscardHandler)
	state := t.TempDir()
	stale := filepath.Join(t.TempDir(), "bp1")
	require.NoError(t, os.Mkdir(stale, 0o700))
	runs := filepath.Join(state, pluginRunsDirName)
	require.NoError(t, os.Mkdir(runs, 0o700))
	rec := fmt.Sprintf(`{"pid":99999999,"start":"gone","socketDir":%q,"enginePid":99999998,"engineStart":"gone"}`, stale)
	require.NoError(t, os.WriteFile(filepath.Join(runs, "99999999.json"), []byte(rec), 0o600))

	require.Nil(t, pluginRuns(config.Config{Mode: config.ModeService}, state, 0, discard))
	require.Nil(t, pluginRuns(config.Config{}, state, 0, discard))
	_, err := os.Lstat(stale)
	require.NoError(t, err, "nothing reaped by an engine that records nothing")

	r := pluginRuns(config.Config{Mode: config.ModeService}, state, os.Geteuid(), discard)
	require.NotNil(t, r)
	require.Equal(t, runs, r.Dir)
	_, err = os.Lstat(stale)
	require.ErrorIs(t, err, os.ErrNotExist, "the earlier run's socket directory is removed")
	left, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, left)
}
