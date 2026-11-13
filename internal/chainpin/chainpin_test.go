package chainpin_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

func TestFileRoundTrip(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state")
	f := chainpin.File{Dir: dir}

	_, ok, err := f.Load("bot")
	require.NoError(t, err)
	require.False(t, ok, "no pin yet")

	head := chainpin.Pin{Head: guard.ChainHead{Seq: 42, Hash: []byte{1, 2, 3}}, Install: 16384}
	require.NoError(t, f.Save("bot", head))
	got, ok, err := f.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, head, got)

	info, err := os.Stat(filepath.Join(dir, "bot.head.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	next := chainpin.Pin{Head: guard.ChainHead{Seq: 43, Hash: []byte{4}}}
	require.NoError(t, f.Save("bot", next))
	got, _, err = f.Load("bot")
	require.NoError(t, err)
	require.Equal(t, next, got)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temp files left behind")
}

func TestFileRefusesBadNamesAndContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := chainpin.File{Dir: dir}
	for _, name := range []string{"", "../x", "a/b", "Bot", "a.b"} {
		require.ErrorIs(t, f.Save(name, chainpin.Pin{Head: guard.Genesis()}), chainpin.ErrInvalidName, name)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.head.json"), []byte(`{"seq":1,"hash":"zz"}`), 0o600))
	_, _, err := f.Load("bad")
	require.Error(t, err)
}

func TestMemory(t *testing.T) {
	t.Parallel()
	var m chainpin.Memory
	_, ok, err := m.Load("bot")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, m.Save("bot", chainpin.Pin{Head: guard.Genesis(), Install: 7}))
	got, ok, err := m.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, chainpin.Pin{Head: guard.Genesis(), Install: 7}, got)
}

// A pin belongs to the install it was saved on; one saved before installs
// were told apart (0) is taken as the current one.
func TestPinOfInstall(t *testing.T) {
	t.Parallel()
	require.True(t, chainpin.Pin{Install: 5}.Of(5))
	require.False(t, chainpin.Pin{Install: 5}.Of(6))
	require.True(t, chainpin.Pin{}.Of(6))
}
