package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestKeygenSignVerify: a directory signed with a keygen key passes Verify
// once its public key is trusted, and fails after a 1-byte change.
func TestKeygenSignVerify(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	keys, err := WriteKeyPair(filepath.Join(f.base, "keys"))
	require.NoError(t, err)
	fi, err := os.Stat(keys.PrivatePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	require.Equal(t, keys.KeyID+PrivateKeyExt, filepath.Base(keys.PrivatePath))
	require.Equal(t, keys.KeyID+PublicKeyExt, filepath.Base(keys.PublicPath))

	priv, err := ReadSigningKey(keys.PrivatePath)
	require.NoError(t, err)
	src := filepath.Join(f.base, "authored")
	f.writeLocal(src, f.signer)
	require.NoError(t, os.Remove(filepath.Join(src, SignatureFile)))
	sigPath, id, err := SignDir(src, priv)
	require.NoError(t, err)
	require.Equal(t, keys.KeyID, id)
	require.Equal(t, filepath.Join(src, SignatureFile), sigPath)

	_, err = Install(src, f.root, "authored", f.trust, ModeSameUser)
	requireNoSecrets(t, err)
	require.Contains(t, err.Error(), "NOT_TRUSTED", "an untrusted key's signature does not pass")

	pub, err := os.ReadFile(keys.PublicPath)
	require.NoError(t, err)
	trustedID, _, err := f.trust.Add(pub)
	require.NoError(t, err)
	require.Equal(t, keys.KeyID, trustedID)
	v, err := Install(src, f.root, "authored", f.trust, ModeSameUser)
	require.NoError(t, err)
	_, err = Verify(f.root, EntryKey{Name: "acme-ner", Instance: "authored"}, v.ManifestSHA256, f.trust, ModeSameUser)
	require.NoError(t, err)
	require.Equal(t, keys.KeyID, v.SignerKeyID)

	// One byte of the manifest changed after signing fails.
	mp := filepath.Join(src, ManifestFile)
	b, err := os.ReadFile(mp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mp, append(b, ' '), 0o644))
	_, err = Install(src, f.root, "changed", f.trust, ModeSameUser)
	requireNoSecrets(t, err)
	require.Contains(t, err.Error(), "NOT_TRUSTED")
}

func TestKeygenNeverOverwrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keys, err := WriteKeyPair(dir)
	require.NoError(t, err)
	before, err := os.ReadFile(keys.PrivatePath)
	require.NoError(t, err)
	require.NoError(t, writeExclusive(filepath.Join(dir, "x"), []byte("a"), privateKeyMode))
	require.ErrorContains(t, writeExclusive(filepath.Join(dir, "x"), []byte("b"), privateKeyMode), "never overwrites")
	require.ErrorContains(t, writeExclusive(keys.PrivatePath, []byte("b"), privateKeyMode), "never overwrites")
	after, err := os.ReadFile(keys.PrivatePath)
	require.NoError(t, err)
	require.Equal(t, before, after)

	// A symlink planted at the name is not followed.
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "link")))
	require.Error(t, writeExclusive(filepath.Join(dir, "link"), []byte("b"), privateKeyMode))
	_, err = os.Stat(target)
	require.True(t, os.IsNotExist(err))
}

func TestReadSigningKeyRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keys, err := WriteKeyPair(dir)
	require.NoError(t, err)

	require.NoError(t, os.Chmod(keys.PrivatePath, 0o640))
	_, err = ReadSigningKey(keys.PrivatePath)
	require.ErrorContains(t, err, "readable by you only")
	require.NoError(t, os.Chmod(keys.PrivatePath, 0o400))
	_, err = ReadSigningKey(keys.PrivatePath)
	require.NoError(t, err, "narrower than 0600 is fine")
	require.NoError(t, os.Chmod(keys.PrivatePath, 0o600))

	link := filepath.Join(dir, "link.key")
	require.NoError(t, os.Symlink(keys.PrivatePath, link))
	_, err = ReadSigningKey(link)
	require.ErrorContains(t, err, "symlink")

	// The public key is not a private key; the error never quotes either.
	_, err = ReadSigningKey(keys.PublicPath + "x")
	require.Error(t, err)
	require.NoError(t, os.Chmod(keys.PublicPath, 0o600))
	_, err = ReadSigningKey(keys.PublicPath)
	require.Error(t, err)
	requireNoSecrets(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "key file "+keys.PublicPath))
}

func TestSignDirChecksFiles(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	src := filepath.Join(f.base, "authored")
	f.writeLocal(src, f.signer)
	sig := filepath.Join(src, SignatureFile)
	before, err := os.ReadFile(sig)
	require.NoError(t, err)

	bin := filepath.Join(src, "bin", "acme-ner")
	require.NoError(t, os.WriteFile(bin, []byte(testBinary+"x"), 0o755))
	_, _, err = SignDir(src, f.signer)
	requireNoSecrets(t, err)
	require.Contains(t, err.Error(), bin)
	require.NoError(t, os.WriteFile(bin, []byte(testBinary), 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(src, ManifestFile), []byte(`{"manifestVersion": 1, "name": "acme-ner", "hooks": {"wire.verdict": {}}}`), 0o644))
	_, _, err = SignDir(src, f.signer)
	require.ErrorContains(t, err, "BAD_MANIFEST")
	after, err := os.ReadFile(sig)
	require.NoError(t, err)
	require.Equal(t, before, after, "a refused directory keeps its old signature")
}
