//go:build unix

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
)

// The host's RootEngineKey hands the adapter the engine's own mode for its
// state directory: a missing one's hint names engine.StateDirMode.
func TestSetupHostRootEngineKeyNamesTheEnginesStateDirMode(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "basalt")
	trusted, err := credfiles.RootTrustedOwner(dir)
	require.NoError(t, err)
	cfg, err := setupHost{}.OpenRootConfigDir(dir, trusted)
	require.NoError(t, err)
	defer cfg.Close()
	state := filepath.Join(root, "state")
	_, err = setupHost{}.RootEngineKey(state, runtime.GOOS, cfg, time.Now)
	require.ErrorContains(t, err, fmt.Sprintf("sudo install -d -m %04o -o %d %s", engine.StateDirMode, os.Geteuid(), state))
}
