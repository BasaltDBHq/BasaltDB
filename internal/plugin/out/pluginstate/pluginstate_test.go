package pluginstate_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginstate"
)

func TestWriteFeedCursorMakesTheDirectoryAndAPrivateFile(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "plugin-cursors", "slack", "main")
	require.NoError(t, pluginstate.WriteFeedCursor(dir, "bot.json", []byte(`{"seq":1}`)))
	require.NoError(t, pluginstate.WriteFeedCursor(dir, "bot.json", []byte(`{"seq":2}`)))

	raw, err := os.ReadFile(filepath.Join(dir, "bot.json"))
	require.NoError(t, err)
	require.Equal(t, `{"seq":2}`, string(raw))
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, "bot.json"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		di, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), di.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file left behind")
}
