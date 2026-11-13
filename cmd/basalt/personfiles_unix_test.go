//go:build unix

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const rootOnlySecret = "user=ROOT-ONLY-SECRET"

// rootCLIFixture is an engine config dir as basalt init lays it out
// (engine.json, agents/bot.url), and a secret elsewhere that only root
// should read. The CLI runs as root (fake euid 0).
type rootCLIFixture struct {
	c                        *cliIO
	configPath, cred, secret string
}

func newRootCLIFixture(t *testing.T) rootCLIFixture {
	t.Helper()
	dir := t.TempDir()
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.Mkdir(agents, 0o700))
	cred := filepath.Join(agents, "bot.url")
	require.NoError(t, os.WriteFile(cred, []byte(agentCfgURL+"\n"), 0o600))
	secretDir := filepath.Join(dir, "rootonly")
	require.NoError(t, os.Mkdir(secretDir, 0o700))
	secret := filepath.Join(secretDir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte(rootOnlySecret+"\n"), 0o600))
	configPath := filepath.Join(dir, "engine.json")
	writeEngineJSON(t, configPath, cred)
	h := newFakeHost(t)
	h.euid = 0
	return rootCLIFixture{c: &cliIO{host: h, getenv: func(string) string { return "" }}, configPath: configPath, cred: cred, secret: secret}
}

func writeEngineJSON(t *testing.T, path, cred string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"socketDir": "/tmp/basalt-test",
		"agents":    []map[string]string{{"name": testAgentKey, "osUser": "tester", "credentialFile": cred}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

func TestRootCLIReadsAPlainCredential(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	got, err := agentURL(f.c, testAgentKey, "", f.configPath)
	require.NoError(t, err)
	require.Equal(t, agentCfgURL, got)
	got, err = agentURL(f.c, "", f.cred, f.configPath)
	require.NoError(t, err)
	require.Equal(t, agentCfgURL, got)
}

func TestRootCLIRefusesLinkedEngineFiles(t *testing.T) {
	t.Parallel()
	for name, plant := range map[string]func(t *testing.T, f rootCLIFixture){
		"credential symlink": func(t *testing.T, f rootCLIFixture) {
			require.NoError(t, os.Remove(f.cred))
			require.NoError(t, os.Symlink(f.secret, f.cred))
		},
		"credential hardlink": func(t *testing.T, f rootCLIFixture) {
			require.NoError(t, os.Remove(f.cred))
			require.NoError(t, os.Link(f.secret, f.cred))
		},
		"agents dir symlink": func(t *testing.T, f rootCLIFixture) {
			agents := filepath.Dir(f.cred)
			require.NoError(t, os.RemoveAll(agents))
			require.NoError(t, os.Symlink(filepath.Dir(f.secret), agents))
			require.NoError(t, os.Rename(f.secret, filepath.Join(filepath.Dir(f.secret), "bot.url")))
		},
		"config symlink": func(t *testing.T, f rootCLIFixture) {
			other := filepath.Join(filepath.Dir(f.secret), "engine.json")
			writeEngineJSON(t, other, f.secret)
			require.NoError(t, os.Remove(f.configPath))
			require.NoError(t, os.Symlink(other, f.configPath))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRootCLIFixture(t)
			plant(t, f)
			got, err := agentURL(f.c, testAgentKey, "", f.configPath)
			require.Error(t, err)
			require.Empty(t, got)
			require.NotContains(t, err.Error(), rootOnlySecret)
		})
	}
}

func TestRootCLIRefusesALinkedCredentialFlag(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	link := filepath.Join(filepath.Dir(f.cred), "direct.url")
	require.NoError(t, os.Symlink(f.secret, link))
	_, err := agentURL(f.c, "", link, f.configPath)
	require.ErrorContains(t, err, "symlink")
}

func TestPersonCLIStillReadsItsOwnFilesAsUsual(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	f.c.host.(*fakeHost).euid = 501
	got, err := agentURL(f.c, testAgentKey, "", f.configPath)
	require.NoError(t, err)
	require.Equal(t, agentCfgURL, got)
}
