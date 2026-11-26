package plugin

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// vectorDir is a signed plugin the plugin SDK (basalt-plugin-go) holds
// byte for byte: the manifest, the file it lists, and one signature made by
// this package's SignManifest and one made by the SDK's basalt-plugin sign.
// ECDSA signatures are not reproducible, so the vector fixes the inputs and a
// signature from each side, and each side verifies both. The directory is the
// same in the SDK's repository (plugintool/testdata/sign-vector).
const vectorDir = "testdata/sign-vector"

func vectorFile(t *testing.T, elem ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{vectorDir}, elem...)...))
	require.NoError(t, err)
	return b
}

// TestSignaturesMadeByTheSDKVerify: a plugin signed by the SDK is installed
// and verified through the real trust store and Verify, as the engine does,
// exactly like one signed by this package.
func TestSignaturesMadeByTheSDKVerify(t *testing.T) {
	t.Parallel()
	for _, signer := range []string{"sdk", "engine"} {
		t.Run(signer, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			dir := filepath.Join(f.base, "vector")
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, ManifestFile), vectorFile(t, "plugin", ManifestFile), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "bin", "acme-ner"), vectorFile(t, "plugin", "bin", "acme-ner"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, SignatureFile), vectorFile(t, signer+".sig"), 0o644))
			pub, id, err := ParsePublicKey(vectorFile(t, signer+".pub"))
			require.NoError(t, err)
			f.trustKey(pub)

			v, err := installCopy(dir, f.root, "default", f.trust)
			require.NoError(t, err)
			require.Equal(t, id, v.SignerKeyID)

			// One byte of the manifest and the signature no longer verifies.
			manifest := vectorFile(t, "plugin", ManifestFile)
			sigKeyID, sig, err := parseSignatureFile(vectorFile(t, signer+".sig"))
			require.NoError(t, err)
			require.Equal(t, id, sigKeyID)
			require.True(t, verifyManifestSig(pub, manifest, sig))
			require.False(t, verifyManifestSig(pub, append([]byte(" "), manifest...), sig))
		})
	}
}

// valuePattern matches the two values of a signature file that differ from
// one signature to the next.
var valuePattern = regexp.MustCompile(`("(?:keyId|sig)": ")[A-Za-z0-9_-]+(")`)

// TestSDKSignatureFileHasTheLayoutTheEngineWrites: but for the key id and the
// signature, the SDK's file is byte for byte the file this package writes:
// the same fields in the same order, indent and final newline.
func TestSDKSignatureFileHasTheLayoutTheEngineWrites(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	require.NoError(t, err)
	mine, err := SignManifest(vectorFile(t, "plugin", ManifestFile), key)
	require.NoError(t, err)
	shape := func(b []byte) string { return valuePattern.ReplaceAllString(string(b), "${1}x${2}") }
	require.Equal(t, shape(mine), shape(vectorFile(t, "sdk.sig")))
	require.Equal(t, shape(mine), shape(vectorFile(t, "engine.sig")))
}
