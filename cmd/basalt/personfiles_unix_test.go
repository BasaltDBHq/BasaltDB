//go:build unix

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/links"
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

// The ownership rule at the core of readCredentialAsRoot: a plain file with
// one link, mode 0600, is still refused when it does not belong to the
// trusted user.
func TestRootCLIRefusesACredentialOwnedByAnotherUser(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	_, err := readCredentialAsRoot(f.cred, os.Getuid()+1, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refused")
	got, err := readCredentialAsRoot(f.cred, os.Getuid(), true)
	require.NoError(t, err, "the same file passes for its owner")
	require.Equal(t, agentCfgURL, got)
}

// As root, the config reads behind log's dictionary line, access's commands
// and the pages links go through the hardened read: a FIFO swapped in for
// the config does not hang them, and a link is not followed.
func TestRootCLIConfigReadsDoNotFollowLinksOrBlockOnAFIFO(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	dir := filepath.Dir(f.configPath)
	fifo := filepath.Join(dir, "fifo.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	hosted := filepath.Join(t.TempDir(), "hosted.json")
	require.NoError(t, os.WriteFile(hosted, []byte(`{"socketDir": "/s", "pagesUrl": "https://console.basaltvault.app",
		"agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c"}]}`), 0o600))
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.Symlink(hosted, link))

	// The reads run on another goroutine so a hang fails the test instead
	// of blocking it; their results are checked back here.
	type result struct {
		path, base, local string
		known             bool
		dictNil           bool
	}
	results := make(chan []result, 1)
	go func() {
		paths := []string{fifo, link}
		out := make([]result, 0, len(paths))
		for _, path := range paths {
			_, known := accessCommands(f.c, "bot", path)
			out = append(out, result{
				path: path, base: configuredBase(f.c, "", "bot", path), local: localPages(f.c, "", "bot", path),
				known: known, dictNil: statusDictionary(f.c, path) == nil,
			})
		}
		results <- out
	}()
	select {
	case got := <-results:
		for _, r := range got {
			require.Equal(t, links.DefaultLocal, r.base, r.path)
			require.Empty(t, r.local, r.path)
			require.False(t, r.known, r.path)
			require.True(t, r.dictNil, r.path)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a config read blocked on the FIFO")
	}

	// A plain config in the same directory is read as root.
	plain := filepath.Join(dir, "plain.json")
	raw, err := os.ReadFile(hosted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(plain, raw, 0o600))
	require.Equal(t, links.HostedConsole, configuredBase(f.c, "", "bot", plain), "the hardened read still reads a plain config")

	user := &cliIO{host: newFakeHost(t), getenv: func(string) string { return "" }}
	require.Equal(t, links.HostedConsole, configuredBase(user, "", "bot", link), "not as root: the plain read follows the link")
}
