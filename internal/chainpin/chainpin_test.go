package chainpin_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// Install ids for the tests.
var (
	installA = uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2b")
	installB = uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2c")
)

func TestFileRoundTrip(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state")
	f := chainpin.File{Dir: dir}

	_, ok, err := f.Load("bot")
	require.NoError(t, err)
	require.False(t, ok, "no pin yet")

	head := chainpin.Pin{Head: guard.ChainHead{Seq: 42, Hash: []byte{1, 2, 3}}, Install: installA}
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
	require.NoError(t, m.Save("bot", chainpin.Pin{Head: guard.Genesis(), Install: installA}))
	got, ok, err := m.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, chainpin.Pin{Head: guard.Genesis(), Install: installA}, got)
}

// A pin belongs to the install it was saved on; one saved before install
// ids (none) is of no install, so it is settled, never checked as the
// current one's.
func TestPinOfInstall(t *testing.T) {
	t.Parallel()
	require.True(t, chainpin.Pin{Install: installA}.Of(installA))
	require.False(t, chainpin.Pin{Install: installA}.Of(installB))
	require.False(t, chainpin.Pin{}.Of(installB))
	require.False(t, chainpin.Pin{}.Of(uuid.Nil))
}

// A pin file written before install ids carries the schema oid as a number
// under "install". It still loads, with no install, so it is settled.
func TestFileLoadsAPinSavedBeforeInstallIDs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bot.head.json"),
		[]byte(`{"seq":1,"hash":"0102","install":16437}`), 0o600))
	got, ok, err := chainpin.File{Dir: dir}.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, chainpin.Pin{Head: guard.ChainHead{Seq: 1, Hash: []byte{1, 2}}}, got)
	require.False(t, got.Of(installA))
}

// A pin keeps each set-aside once, and the file round-trips them.
func TestPinKeepsItsSetAside(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	s := guard.SetAside{PinnedSeq: 42, PinnedHash: []byte{1, 2}, PinnedInstall: installA, Install: installB, At: at}
	p := chainpin.Pin{Head: guard.Genesis(), Install: installB}.Kept(s).Kept(s)
	require.Len(t, p.SetAside, 1)
	other := s
	other.PinnedSeq = 43
	p = p.Kept(other)
	require.Len(t, p.SetAside, 2)

	f := chainpin.File{Dir: t.TempDir()}
	require.NoError(t, f.Save("bot", p))
	got, ok, err := f.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, p, got)
	raw, err := os.ReadFile(filepath.Join(f.Dir, "bot.head.json"))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"setAside":[{"pinnedSeq":42,"pinnedHash":"0102","pinnedInstallId":"`+installA.String()+
		`","installId":"`+installB.String()+`","at":"2026-11-14T09:30:00Z"}`)
}
