package engine

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// The tests that change GOMEMLIMIT do not run in parallel.

func TestOpenPIICreatesTheKeyAndRefusesAWideOne(t *testing.T) {
	limit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(limit) })
	t.Setenv(envGoMemLimit, "")
	dir := filepath.Join(t.TempDir(), "state")
	p := config.Config{}.PIIOrDefault()

	dict, err := openPII(dir, p, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, dict.Close())
	fi, err := os.Stat(filepath.Join(dir, pii.KeyFileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "pii.key is created 0600 on first start")
	fi, err = os.Stat(filepath.Join(dir, pii.DictionaryDirName, pii.StatusFileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "status.json holds counts only, readable by basalt log")
	require.Equal(t, int64(memLimitFactor*config.DefaultPIIMaxMemoryMB)<<20, debug.SetMemoryLimit(-1), "GOMEMLIMIT from the budget")

	// The same key on the next start; a key file wider than 0600 stops it.
	dict, err = openPII(dir, p, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, dict.Close())
	require.NoError(t, os.Chmod(filepath.Join(dir, pii.KeyFileName), 0o640))
	_, err = openPII(dir, p, slog.New(slog.DiscardHandler))
	require.ErrorContains(t, err, "0600")
}

func TestOpenPIIKeepsGOMEMLIMITFromTheEnvironment(t *testing.T) {
	limit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(limit) })
	t.Setenv(envGoMemLimit, "1GiB")
	debug.SetMemoryLimit(1 << 30)
	dict, err := openPII(t.TempDir(), config.PII{MaxMemoryMB: 64}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, dict.Close())
	require.Equal(t, int64(1<<30), debug.SetMemoryLimit(-1))
}
