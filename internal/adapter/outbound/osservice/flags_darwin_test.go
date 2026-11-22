package osservice

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A log or an old log directory its owner made immutable (chflags uchg)
// does not stop the install: root clears the owner's flags first.
func TestOSSystemClearsTheOwnersImmutableFlag(t *testing.T) {
	dir := realTempDir(t)
	cur, err := user.Current()
	require.NoError(t, err)
	t.Cleanup(func() { clearFlagsUnder(t, dir) })

	log := filepath.Join(dir, "p.log")
	require.NoError(t, os.WriteFile(log, []byte("trace\n"), 0o644))
	require.NoError(t, unix.Chflags(log, unix.UF_IMMUTABLE|unix.UF_APPEND))
	require.NoError(t, OSSystem{}.CreateFile(log, 0o600, cur.Username))
	fi, err := os.Lstat(log)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	got, err := os.ReadFile(log)
	require.NoError(t, err)
	require.Equal(t, "trace\n", string(got))
	var st unix.Stat_t
	require.NoError(t, unix.Lstat(log, &st))
	require.Zero(t, st.Flags&unix.UF_SETTABLE, "the owner's flags are cleared, so newsyslog can rotate it")

	logs := filepath.Join(dir, "Basalt")
	require.NoError(t, os.Mkdir(logs, 0o750))
	require.NoError(t, unix.Chflags(logs, unix.UF_IMMUTABLE))
	moved, err := OSSystem{}.MoveAside(logs, cur.Username)
	require.NoError(t, err)
	require.NotEmpty(t, moved)
	_, err = os.Lstat(logs)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// clearFlagsUnder lets t.TempDir's cleanup remove what a test made
// immutable.
func clearFlagsUnder(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
		_ = unix.Chflags(p, 0)
		return nil
	})
}
