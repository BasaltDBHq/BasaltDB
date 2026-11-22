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
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

const rootOnlySecret = "user=ROOT-ONLY-SECRET"

// rootCredURL is the fixture's credential: a URL root takes from a file
// another user owns (pgdial.CheckForeignDSN).
const rootCredURL = "postgres://bot:pw@db.example.com/app?sslmode=require"

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
	require.NoError(t, os.WriteFile(cred, []byte(rootCredURL+"\n"), 0o600))
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
		"agents":    []map[string]any{{"name": testAgentKey, "osUser": "tester", "store": map[string]string{"kind": "POSTGRES", "credentialFile": cred}}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

// The hardened read as root gives the same edit for the old credentialFile.
func TestRootCLINamesTheEditForTheOldCredentialFile(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	require.NoError(t, os.WriteFile(f.configPath, []byte(`{"socketDir": "/tmp/basalt-test", "agents": [{"name": "bot", "osUser": "tester", "credentialFile": "/c/bot.cred"}]}`), 0o600))
	_, err := agentURL(f.c, testAgentKey, "", f.configPath)
	require.ErrorContains(t, err, `agent "bot": "credentialFile" now goes inside "store"; replace "credentialFile": "/c/bot.cred" with "store": {"kind": "POSTGRES", "credentialFile": "/c/bot.cred"}`)
	require.NotContains(t, err.Error(), "unknown field")
}

func TestRootCLIReadsAPlainCredential(t *testing.T) {
	t.Parallel()
	f := newRootCLIFixture(t)
	got, err := agentURL(f.c, testAgentKey, "", f.configPath)
	require.NoError(t, err)
	require.Equal(t, rootCredURL, got)
	got, err = agentURL(f.c, "", f.cred, f.configPath)
	require.NoError(t, err)
	require.Equal(t, rootCredURL, got)
}

// As root, the person CLI connects with the credential it reads, and pgx
// reads files for the caller from some parameters: a credential file
// another user owns (here the test's user, not root) must pass
// pgdial.CheckForeignDSN, read through the config (log, status, upgrade)
// or --credential-file. The refusal never echoes the string. Not as root,
// the same file is the user's own and is taken as it is.
func TestRootCLIChecksAnotherUsersCredential(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("as real root the fixture's files are root's own")
	}
	for name, dsn := range map[string]string{
		"sslrootcert": "postgres://bot:pw@db.example.com/app?sslrootcert=/root/ca.pem",
		"passfile":    "postgres://bot:pw@db.example.com/app?passfile=/root/.pgpass",
		"no password": "postgres://bot@db.example.com/app",
		"key/value":   "host=db.example.com user=bot password=pw sslkey=/root/k",
		"a fragment":  "postgres://bot:pw@db.example.com/app#&passfile=/root/.pgpass",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRootCLIFixture(t)
			require.NoError(t, os.WriteFile(f.cred, []byte(dsn+"\n"), 0o600))
			for _, via := range []struct{ agent, flag string }{{testAgentKey, ""}, {"", f.cred}} {
				got, err := agentURL(f.c, via.agent, via.flag, f.configPath)
				require.ErrorIs(t, err, pgdial.ErrForeignDSN)
				require.Empty(t, got)
				require.ErrorContains(t, err, "not root")
				require.ErrorContains(t, err, "sudo -u <user>")
				require.NotContains(t, err.Error(), "pw@")
				require.NotContains(t, err.Error(), "/root/")
			}
			f.c.host.(*fakeHost).euid = os.Geteuid()
			got, err := agentURL(f.c, testAgentKey, "", f.configPath)
			require.NoError(t, err, "not as root: the user's own file")
			require.Equal(t, dsn, got)
		})
	}
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
	require.Equal(t, rootCredURL, got)
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
	require.Equal(t, rootCredURL, got)
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
	require.NoError(t, os.WriteFile(hosted, []byte(`{"socketDir": "/s", "pagesUrl": "https://portal.basaltvault.app",
		"agents": [{"name": "bot", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}]}`), 0o600))
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.Symlink(hosted, link))

	// The reads run on another goroutine so a hang fails the test instead
	// of blocking it; their results are checked back here.
	type result struct {
		path, base, local string
	}
	results := make(chan []result, 1)
	go func() {
		paths := []string{fifo, link}
		out := make([]result, 0, len(paths))
		for _, path := range paths {
			out = append(out, result{
				path: path, base: configuredBase(f.c, "", "bot", path), local: localPages(f.c, "", "bot", path),
			})
		}
		results <- out
	}()
	select {
	case got := <-results:
		for _, r := range got {
			require.Equal(t, links.DefaultLocal, r.base, r.path)
			require.Empty(t, r.local, r.path)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a config read blocked on the FIFO")
	}

	// A plain config in the same directory is read as root.
	plain := filepath.Join(dir, "plain.json")
	raw, err := os.ReadFile(hosted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(plain, raw, 0o600))
	require.Equal(t, links.Portal, configuredBase(f.c, "", "bot", plain), "the hardened read still reads a plain config")

	user := &cliIO{host: newFakeHost(t), getenv: func(string) string { return "" }}
	require.Equal(t, links.Portal, configuredBase(user, "", "bot", link), "not as root: the plain read follows the link")
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
			require.Equal(t, exitError, r.code, r.stdout)
			_, err := os.Lstat(planted)
			require.ErrorIs(t, err, os.ErrNotExist, "the credential file the config names is never written")
			_, err = os.Lstat(planted + pendingSuffix)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

// checkConfigFile, the hardened read's file check, refuses a config owned
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
	require.NoError(t, checkConfigFile(open(), os.Getuid()))
	require.ErrorContains(t, checkConfigFile(open(), os.Getuid()+1), "owned by uid")
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		require.NoError(t, os.Chmod(f.configPath, mode))
		require.ErrorContains(t, checkConfigFile(open(), os.Getuid()), "writable by group or others", "mode %o", mode)
	}
	require.NoError(t, os.Chmod(f.configPath, 0o644))
	require.NoError(t, checkConfigFile(open(), os.Getuid()), "readable by others is not refused")
}
