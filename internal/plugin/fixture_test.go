package plugin

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Contents of the test plugin's files. They stand in for a binary and a
// model; tests check that no error ever quotes them.
const (
	testBinary = "#!/bin/sh\necho TOP-SECRET-BINARY-BYTES\n"
	testModel  = "TOP-SECRET-MODEL-WEIGHTS"
)

// fixture is a same-user engine under t.TempDir(): a config directory, its
// plugin root, a trust store holding one trusted signing key, and a source
// directory holding a signed local plugin.
type fixture struct {
	t         *testing.T
	base      string
	configDir string
	root      string
	src       string
	signer    *ecdsa.PrivateKey
	trust     TrustStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	// The real path, so the paths errors name match the ones tests build.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	f := &fixture{t: t, base: base, configDir: filepath.Join(base, "config"), src: filepath.Join(base, "src")}
	require.NoError(t, os.Mkdir(f.configDir, 0o700))
	f.root, err = Root(pluginmodel.ModeSameUser, runtime.GOOS, f.configDir)
	require.NoError(t, err)
	f.trust, err = NewTrustStore(pluginmodel.ModeSameUser, runtime.GOOS, f.configDir)
	require.NoError(t, err)
	f.signer, err = GenerateKey()
	require.NoError(t, err)
	f.trustKey(&f.signer.PublicKey)
	f.writeLocal(f.src, f.signer)
	return f
}

func (f *fixture) trustKey(pub *ecdsa.PublicKey) string {
	f.t.Helper()
	pemBytes, err := MarshalPublicKey(pub)
	require.NoError(f.t, err)
	id, _, err := f.trust.Add(pemBytes)
	require.NoError(f.t, err)
	return id
}

func sha(b string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(b))) }

// localManifest is a signed local detector with a binary and a model file.
func localManifest() []byte {
	return fmt.Appendf(nil, `{
  "manifestVersion": 1,
  "name": "acme-ner",
  "version": "1.4.0",
  "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME", "acme-ner.EMPLOYEE_ID"] } },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": %q, "model/weights.bin": %q },
  "network": { "egress": [] }
}
`, sha(testBinary), sha(testModel))
}

const remoteManifest = `{
  "manifestVersion": 1,
  "name": "acme-cloud",
  "version": "2.0.0",
  "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "feed.observe": { "contract": "feed/1" } },
  "endpoint": { "remote": { "transport": "connectrpc", "url": "https://ner.acme.example" } },
  "network": { "egress": ["ner.acme.example:443"] }
}
`

// writeLocal writes the local test plugin, signed by signer, into dir.
func (f *fixture) writeLocal(dir string, signer *ecdsa.PrivateKey) {
	f.t.Helper()
	require.NoError(f.t, os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	require.NoError(f.t, os.MkdirAll(filepath.Join(dir, "model"), 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "bin", "acme-ner"), []byte(testBinary), 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "model", "weights.bin"), []byte(testModel), 0o644))
	// A file the manifest does not list stays behind.
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "README"), []byte("not shipped"), 0o644))
	f.writeSigned(dir, localManifest(), signer)
}

// writeSigned writes manifest and its signature by signer into dir.
func (f *fixture) writeSigned(dir string, manifest []byte, signer *ecdsa.PrivateKey) {
	f.t.Helper()
	require.NoError(f.t, os.MkdirAll(dir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, ManifestFile), manifest, 0o644))
	sig, err := SignManifest(manifest, signer)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, SignatureFile), sig, 0o644))
}

func (f *fixture) install(instance string) pluginmodel.Verified {
	f.t.Helper()
	v, err := Install(f.src, f.root, instance, f.trust, pluginmodel.ModeSameUser)
	require.NoError(f.t, err)
	return v
}

func (f *fixture) verify(instance, manifestSHA string) (pluginmodel.Verified, error) {
	return Verify(f.root, pluginmodel.EntryKey{Name: "acme-ner", Instance: instance}, manifestSHA, f.trust, pluginmodel.ModeSameUser)
}

// requireNoSecrets: an error never quotes a file's contents or a key.
func requireNoSecrets(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	msg := err.Error()
	for _, s := range []string{"TOP-SECRET", "BEGIN", "PRIVATE", "MFkw"} {
		require.NotContains(t, msg, s)
	}
}

// entries lists a directory's names; none when it does not exist.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	out := make([]string, 0, len(des))
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}
