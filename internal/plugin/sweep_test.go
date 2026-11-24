package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

func TestSweepKeepsOnlyTheEntrysCopy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")
	other := f.install("client_x")
	instDir := filepath.Dir(v.Dir)
	// What a crashed add leaves, and a copy no entry references.
	for _, d := range []string{stagingPrefix + "1", oldPrefix + "2", "ffff"} {
		require.NoError(t, os.Mkdir(filepath.Join(instDir, d), 0o755))
	}

	key := pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}
	require.NoError(t, Sweep(f.root, key, v.ManifestSHA256, pluginmodel.ModeSameUser))
	require.Equal(t, []string{v.ManifestSHA256}, entries(t, instDir))
	_, err := f.verify(pluginmodel.DefaultInstance, v.ManifestSHA256)
	require.NoError(t, err, "the kept copy still verifies")

	// Removing the entry removes its directory only: the other instance stays.
	require.NoError(t, Sweep(f.root, key, "", pluginmodel.ModeSameUser))
	require.Empty(t, entries(t, instDir))
	_, err = f.verify("client_x", other.ManifestSHA256)
	require.NoError(t, err, "another instance shares nothing")

	require.NoError(t, Sweep(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: "client_x"}, "", pluginmodel.ModeSameUser))
	require.Empty(t, entries(t, filepath.Join(f.root, "acme-ner")))
	require.NoError(t, Sweep(f.root, key, "", pluginmodel.ModeSameUser), "a missing directory is not an error")
}

func TestSweepRefusesAWritableDirectory(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.install("")
	nameDir := filepath.Join(f.root, "acme-ner")
	require.NoError(t, os.Chmod(nameDir, 0o777))
	t.Cleanup(func() { _ = os.Chmod(nameDir, 0o755) })
	err := Sweep(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: pluginmodel.DefaultInstance}, "", pluginmodel.ModeSameUser)
	require.Error(t, err)
	_, statErr := os.Stat(v.Dir)
	require.NoError(t, statErr, "nothing removed below a directory the path rule refuses")
}
