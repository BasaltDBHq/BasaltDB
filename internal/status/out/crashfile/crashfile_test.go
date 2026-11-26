package crashfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/status/out/crashfile"
)

// The first directory that holds the report names its file.
func TestFindTakesTheFirstDirectory(t *testing.T) {
	t.Parallel()
	a, b := t.TempDir(), t.TempDir()
	require.Empty(t, crashfile.Find([]string{a, b}, "r1"))
	require.NoError(t, os.WriteFile(filepath.Join(b, "r1.json"), []byte("{}"), 0o600))
	require.Equal(t, filepath.Join(b, "r1.json"), crashfile.Find([]string{a, b}, "r1"))
	require.NoError(t, os.WriteFile(filepath.Join(a, "r1.json"), []byte("{}"), 0o600))
	require.Equal(t, filepath.Join(a, "r1.json"), crashfile.Find([]string{a, b}, "r1"))
	require.Empty(t, crashfile.Find(nil, "r1"))
}
