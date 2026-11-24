//go:build unix

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

const rootOnlySecret = "user=ROOT-ONLY-SECRET"

// rootCredURL is the fixture's credential: a URL root takes from a file
// another user owns (pgdial.CheckForeignDSN).
const rootCredURL = "postgres://bot:pw@db.example.com/app?sslmode=require"

// rootCLIFixture is an engine config dir as basalt init lays it out
// (engine.json, agents/bot.url), and a secret elsewhere that only root
// should read. The CLI runs as root (fake euid 0).
type rootCLIFixture struct {
	c                        *cli.IO
	configPath, cred, secret string
}

func newRootCLIFixture(t *testing.T) rootCLIFixture {
	t.Helper()
	dir := t.TempDir()
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.Mkdir(agents, 0o700))
	cred := filepath.Join(agents, "bot.url")
	require.NoError(t, os.WriteFile(cred, []byte(rootCredURL+"\n"), 0o600))
	secretDir := filepath.Join(dir, "rootonly")
	require.NoError(t, os.Mkdir(secretDir, 0o700))
	secret := filepath.Join(secretDir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte(rootOnlySecret+"\n"), 0o600))
	configPath := filepath.Join(dir, "engine.json")
	writeEngineJSON(t, configPath, cred)
	h := newFakeHost(t)
	h.euid = 0
	return rootCLIFixture{c: &cli.IO{Host: h, Shell: shell{}, Getenv: func(string) string { return "" }}, configPath: configPath, cred: cred, secret: secret}
}

func writeEngineJSON(t *testing.T, path, cred string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"socketDir": "/tmp/basalt-test",
		"agents":    []map[string]any{{"name": testAgentKey, "osUser": "tester", "store": map[string]string{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

// sudo basalt init --remote reads the config with the hardened read before
// it trusts any field: a config writable by others, or a link to a config
// elsewhere, is refused, and the credential file and OS user it names are
// never used.
func TestInitRemoteAsRootRefusesAnUntrustedConfig(t *testing.T) {
	t.Parallel()
	for name, plant := range map[string]func(t *testing.T, cfg, planted string){
		"writable by others": func(t *testing.T, cfg, planted string) {
			writeEngineJSON(t, cfg, planted)
			require.NoError(t, os.Chmod(cfg, 0o666))
		},
		"credential file outside the config's directory": func(t *testing.T, cfg, planted string) {
			// A plain 0600 config its directory's owner wrote: the hardened
			// read accepts it, but root writes only where basalt put the
			// credential, never where the config says.
			writeEngineJSON(t, cfg, planted)
		},
		"symlink": func(t *testing.T, cfg, planted string) {
			other := filepath.Join(t.TempDir(), "engine.json")
			writeEngineJSON(t, other, planted)
			require.NoError(t, os.Remove(cfg))
			require.NoError(t, os.Symlink(other, cfg))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := withState(t, tempConfig(t))
			remote(t, cfg, "--agent", testAgentKey)
			planted := filepath.Join(t.TempDir(), "planted.url")
			plant(t, cfg, planted)

			r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", testAgentKey)
			require.Equal(t, cli.ExitError, r.code, r.stdout)
			_, err := os.Lstat(planted)
			require.ErrorIs(t, err, os.ErrNotExist, "the credential file the config names is never written")
			_, err = os.Lstat(planted + setup.PendingSuffix)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

// cli.CheckConfigFile, the hardened read's file check, refuses a config owned
// by anyone but root or the trusted user, and one writable by group or
// others, and accepts the plain 0600 file of its owner.
func TestRootConfigCheckRefusesAnotherOwnerOrAnOpenMode(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	open := func() *os.File {
		fh, err := os.Open(f.configPath)
		require.NoError(t, err)
		t.Cleanup(func() { fh.Close() })
		return fh
	}
	require.NoError(t, cli.CheckConfigFile(open(), os.Getuid()))
	require.ErrorContains(t, cli.CheckConfigFile(open(), os.Getuid()+1), "owned by uid")
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		require.NoError(t, os.Chmod(f.configPath, mode))
		require.ErrorContains(t, cli.CheckConfigFile(open(), os.Getuid()), "writable by group or others", "mode %o", mode)
	}
	require.NoError(t, os.Chmod(f.configPath, 0o644))
	require.NoError(t, cli.CheckConfigFile(open(), os.Getuid()), "readable by others is not refused")
}
