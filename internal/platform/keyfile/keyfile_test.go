package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

var fixedNow = func() time.Time { return time.Date(2026, 11, 12, 9, 30, 0, 123, time.FixedZone("x", 3600)) }

func keyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), channel.KeyFileName)
}

func TestLoadOrCreateKeysMakesA0600FileOnceAndReusesIt(t *testing.T) {
	t.Parallel()
	path := keyPath(t)
	k1, err := LoadOrCreateKeys(path, fixedNow)
	require.NoError(t, err)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != goosWindows {
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file left behind")

	k2, err := LoadOrCreateKeys(path, time.Now)
	require.NoError(t, err)
	require.Equal(t, k1.EngineID(), k2.EngineID())
	require.Equal(t, k1.BoxPublicKeySPKI(), k2.BoxPublicKeySPKI())
	require.Equal(t, fixedNow().UTC().Truncate(time.Second), k2.CreatedAt())
	k3, err := LoadKeys(path)
	require.NoError(t, err)
	require.Equal(t, k1.EngineID(), k3.EngineID())

	// A signature by the loaded key verifies under the created one's SPKI.
	pub, err := channel.ParseEngineKey(k1.PublicKeySPKI())
	require.NoError(t, err)
	sig, err := k3.Sign(channel.ContextVaultAuth, []byte("challenge\nrelay.basaltvault.app"))
	require.NoError(t, err)
	require.NoError(t, channel.VerifySignature(pub, channel.ContextVaultAuth, []byte("challenge\nrelay.basaltvault.app"), sig))
}

// TestKeyFileHasTheSchemaShape checks the written file against
// api/mcp/vault/channel-key-file.schema.json: its required keys, no others,
// and each field's form.
func TestKeyFileHasTheSchemaShape(t *testing.T) {
	t.Parallel()
	path := keyPath(t)
	k, err := LoadOrCreateKeys(path, fixedNow)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	schemaRaw, err := os.ReadFile("../../../api/mcp/vault/channel-key-file.schema.json")
	require.NoError(t, err)
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(schemaRaw, &schema))

	var file map[string]any
	require.NoError(t, json.Unmarshal(raw, &file))
	for _, key := range schema.Required {
		require.Contains(t, file, key)
	}
	for key := range file {
		require.Contains(t, schema.Properties, key)
	}
	require.InDelta(t, 1, file["format"], 0)
	require.Equal(t, k.EngineID(), file["engineId"])
	require.Equal(t, "2026-11-12T08:30:00Z", file["createdAt"])
	require.Regexp(t, `^[A-Za-z0-9_-]{86}$`, file["boxKeySig"])

	der, err := unb64(file["signingKey"].(string))
	require.NoError(t, err)
	signing, err := x509.ParsePKCS8PrivateKey(der)
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PrivateKey{}, signing)
	der, err = unb64(file["boxKey"].(string))
	require.NoError(t, err)
	_, err = x509.ParsePKCS8PrivateKey(der)
	require.NoError(t, err)

	pub, err := channel.ParseEngineKey(k.PublicKeySPKI())
	require.NoError(t, err)
	sig, err := unb64(file["boxKeySig"].(string))
	require.NoError(t, err)
	statement := []byte(k.EngineID() + "\n" + b64(k.BoxPublicKeySPKI()))
	require.NoError(t, channel.VerifySignature(pub, channel.ContextBoxKey, statement, sig))
}

func TestLoadOrCreateKeysKeepsTheFirstOfTwoConcurrentStarts(t *testing.T) {
	t.Parallel()
	path := keyPath(t)
	const starts = 8
	ids := make([]string, starts)
	var wg sync.WaitGroup
	for i := range starts {
		wg.Go(func() {
			k, err := LoadOrCreateKeys(path, time.Now)
			if err == nil {
				ids[i] = k.EngineID()
			}
		})
	}
	wg.Wait()
	k, err := LoadKeys(path)
	require.NoError(t, err)
	for i, id := range ids {
		require.Equal(t, k.EngineID(), id, i)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestLoadKeysNeverCreates(t *testing.T) {
	t.Parallel()
	path := keyPath(t)
	_, err := LoadKeys(path)
	require.ErrorIs(t, err, channel.ErrKeyFile)
	_, err = os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// writeValid writes a valid key file at a fresh path and returns the path
// and the parsed JSON.
func writeValid(t *testing.T) (string, map[string]any) {
	t.Helper()
	path := keyPath(t)
	_, err := LoadOrCreateKeys(path, fixedNow)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var file map[string]any
	require.NoError(t, json.Unmarshal(raw, &file))
	return path, file
}

// requireRefusedUntouched loads path, expects channel.ErrKeyFile, and checks the
// file is exactly as it was: a refused key file is never replaced.
func requireRefusedUntouched(t *testing.T, path string, msgAndArgs ...any) error {
	t.Helper()
	before, statErr := os.ReadFile(path)
	_, err := LoadOrCreateKeys(path, time.Now)
	require.ErrorIs(t, err, channel.ErrKeyFile, msgAndArgs...)
	after, afterErr := os.ReadFile(path)
	require.Equal(t, statErr == nil, afterErr == nil, msgAndArgs...)
	require.Equal(t, before, after, msgAndArgs...)
	return err
}

func rewrite(t *testing.T, path string, file map[string]any) {
	t.Helper()
	raw, err := json.Marshal(file)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

func TestLoadKeysRefusesAWideModeAndLeavesIt(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == goosWindows {
		t.Skip("POSIX modes")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o606, 0o601} {
		path, file := writeValid(t)
		require.NoError(t, os.Chmod(path, mode))
		err := requireRefusedUntouched(t, path, mode)
		require.ErrorContains(t, err, "0600")
		requireNoKeyMaterial(t, err, file)
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, mode, fi.Mode().Perm(), "the mode is left for the person to fix")
	}
}

func TestLoadKeysRefusesASymlinkOrADirectory(t *testing.T) {
	t.Parallel()
	target, _ := writeValid(t)
	link := keyPath(t)
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	err := requireRefusedUntouched(t, link)
	require.ErrorContains(t, err, "regular file")

	dir := keyPath(t)
	require.NoError(t, os.Mkdir(dir, 0o700))
	_, err = LoadOrCreateKeys(dir, time.Now)
	require.ErrorIs(t, err, channel.ErrKeyFile)
	require.ErrorContains(t, err, "regular file")

	dangling := keyPath(t)
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), dangling))
	_, err = LoadOrCreateKeys(dangling, time.Now)
	require.ErrorIs(t, err, channel.ErrKeyFile, "a dangling link is not a missing file")
	_, err = os.Lstat(filepath.Join(filepath.Dir(dangling), "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoadKeysRefusesAnInvalidFileAndLeavesIt(t *testing.T) {
	t.Parallel()
	_, otherFile := writeValid(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)

	cases := map[string]func(map[string]any){
		"format 2":                func(f map[string]any) { f["format"] = 2 },
		"no format":               func(f map[string]any) { delete(f, "format") },
		"an unknown field":        func(f map[string]any) { f["note"] = "x" },
		"no boxKey":               func(f map[string]any) { delete(f, "boxKey") },
		"another engine's id":     func(f map[string]any) { f["engineId"] = otherFile["engineId"] },
		"a short engine id":       func(f map[string]any) { f["engineId"] = "abc" },
		"another file's box key":  func(f map[string]any) { f["boxKey"] = otherFile["boxKey"] },
		"another file's box sig":  func(f map[string]any) { f["boxKeySig"] = otherFile["boxKeySig"] },
		"a P-384 signing key":     func(f map[string]any) { f["signingKey"] = b64(p384DER) },
		"a signing key not DER":   func(f map[string]any) { f["signingKey"] = "AAAA" },
		"a padded signing key":    func(f map[string]any) { f["signingKey"] = f["signingKey"].(string) + "=" },
		"a bad createdAt":         func(f map[string]any) { f["createdAt"] = "yesterday" },
		"a malformed rotatedFrom": func(f map[string]any) { f["rotatedFrom"] = map[string]any{"engineId": "x"} },
		"the signing key as the box key": func(f map[string]any) {
			f["boxKey"] = f["signingKey"]
		},
	}
	for name, change := range cases {
		path, file := writeValid(t)
		change(file)
		rewrite(t, path, file)
		err := requireRefusedUntouched(t, path, name)
		requireNoKeyMaterial(t, err, file)
	}

	for name, raw := range map[string]string{
		"empty":          "",
		"not JSON":       "channel",
		"an array":       "[]",
		"trailing data":  `{"format":1} {}`,
		"invalid UTF-8":  "\xff",
		"a JSON string":  `"x"`,
		"over 8 KiB":     `{"format":1,"engineId":"` + strings.Repeat("a", keyFileMax) + `"}`,
		"truncated JSON": `{"format":1,`,
	} {
		path := keyPath(t)
		require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
		requireRefusedUntouched(t, path, name)
	}
}

// TestLoadKeysRefusesABoxKeySignedByAnotherKey: the box key's signature is checked,
// so a box key swapped in with its own self-made signature is refused.
func TestLoadKeysRefusesABoxKeySignedByAnotherKey(t *testing.T) {
	t.Parallel()
	path, file := writeValid(t)
	strangerRaw, stranger, err := channel.NewKeyFile(time.Now)
	require.NoError(t, err)
	sig, err := stranger.Sign(channel.ContextBoxKey, []byte(file["engineId"].(string)+"\n"+b64(stranger.BoxPublicKeySPKI())))
	require.NoError(t, err)
	var strangerFile map[string]any
	require.NoError(t, json.Unmarshal(strangerRaw, &strangerFile))
	file["boxKey"] = strangerFile["boxKey"]
	file["boxKeySig"] = b64(sig)
	rewrite(t, path, file)
	err = requireRefusedUntouched(t, path)
	require.ErrorContains(t, err, "boxKeySig")
}

func requireNoKeyMaterial(t *testing.T, err error, file map[string]any) {
	t.Helper()
	for _, field := range []string{"signingKey", "boxKey"} {
		if v, ok := file[field].(string); ok && len(v) > 8 {
			require.NotContains(t, err.Error(), v)
			require.NotContains(t, err.Error(), v[:16])
		}
	}
}

func TestLoadOrCreateKeysFailsWhenItCannotWrite(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == goosWindows || os.Getuid() == 0 {
		t.Skip("POSIX permissions as a normal user")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := LoadOrCreateKeys(filepath.Join(dir, channel.KeyFileName), time.Now)
	require.ErrorIs(t, err, channel.ErrKeyFile)
}

func TestLoadKeysRefusesAStateDirectoryOthersCanWrite(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == goosWindows {
		t.Skip("POSIX modes")
	}
	for _, mode := range []os.FileMode{0o770, 0o720, 0o702, 0o777} {
		path, _ := writeValid(t)
		dir := filepath.Dir(path)
		require.NoError(t, os.Chmod(dir, mode))
		err := requireRefusedUntouched(t, path, mode)
		require.ErrorContains(t, err, "state directory")
		_, err = LoadKeys(path)
		require.ErrorIs(t, err, channel.ErrKeyFile, mode)

		fresh := filepath.Join(dir, "fresh-"+channel.KeyFileName)
		_, err = LoadOrCreateKeys(fresh, time.Now)
		require.ErrorIs(t, err, channel.ErrKeyFile, mode)
		_, err = os.Lstat(fresh)
		require.ErrorIs(t, err, os.ErrNotExist, "nothing is created in such a directory")
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	// Read-only for group and others is fine.
	path, _ := writeValid(t)
	require.NoError(t, os.Chmod(filepath.Dir(path), 0o755))
	_, err := LoadKeys(path)
	require.NoError(t, err)
}

func TestLoadKeysRefusesAStateDirectoryThatIsALink(t *testing.T) {
	t.Parallel()
	path, _ := writeValid(t)
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Skip("no symlinks here")
	}
	_, err := LoadKeys(filepath.Join(link, channel.KeyFileName))
	require.ErrorIs(t, err, channel.ErrKeyFile)
	require.ErrorContains(t, err, "not a link")
}

func TestLoadOrCreateKeysRemovesStaleTemps(t *testing.T) {
	t.Parallel()
	path := keyPath(t)
	dir := filepath.Dir(path)
	stale := filepath.Join(dir, channel.KeyFileName+".123.tmp")
	fresh := filepath.Join(dir, channel.KeyFileName+".456.tmp")
	unrelated := filepath.Join(dir, "other.json.789.tmp")
	for _, p := range []string{stale, fresh, unrelated} {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	}
	old := time.Now().Add(-2 * time.Minute) // older than ownerfile's stale age
	require.NoError(t, os.Chtimes(stale, old, old))
	require.NoError(t, os.Chtimes(unrelated, old, old))

	_, err := LoadOrCreateKeys(path, time.Now)
	require.NoError(t, err)
	_, err = os.Lstat(stale)
	require.ErrorIs(t, err, os.ErrNotExist, "a stale temp is removed")
	_, err = os.Lstat(fresh)
	require.NoError(t, err, "a recent temp may be a concurrent start's")
	_, err = os.Lstat(unrelated)
	require.NoError(t, err, "only this key file's temps")
}
