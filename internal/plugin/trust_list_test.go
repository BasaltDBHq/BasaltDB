package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// TestAddedKeys: the keys the person added are listed by id, in order; a
// file that is not a trusted key is not, and the built-in keys never are.
func TestAddedKeys(t *testing.T) {
	t.Parallel()
	empty, err := NewTrustStore(testFiles, pluginmodel.ModeSameUser, runtime.GOOS, t.TempDir())
	require.NoError(t, err)
	none, err := empty.AddedKeys()
	require.NoError(t, err)
	require.Empty(t, none, "a store that does not exist holds no key")

	f := newFixture(t)
	signerID, err := KeyID(&f.signer.PublicKey)
	require.NoError(t, err)
	other, err := GenerateKey()
	require.NoError(t, err)
	otherID := f.trustKey(&other.PublicKey)

	impostor, err := GenerateKey()
	require.NoError(t, err)
	impostorPEM, err := MarshalPublicKey(&impostor.PublicKey)
	require.NoError(t, err)
	// Under a name that is not its own id, and a file that holds no key.
	require.NoError(t, os.WriteFile(filepath.Join(f.trust.Dir(), "AAAAAAAAAAAAAAAAAAAAAA"+trustFileExt), impostorPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(f.trust.Dir(), "BBBBBBBBBBBBBBBBBBBBBB"+trustFileExt), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(f.trust.Dir(), "notes.txt"), []byte("x"), 0o644))

	keys, err := f.trust.AddedKeys()
	require.NoError(t, err)
	want := []string{signerID, otherID}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	require.Equal(t, want, keys)
	for id := range f.trust.embedded {
		require.NotContains(t, keys, id)
	}
}
