//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// requireEmptyDir fails when dir holds anything: root wrote nothing there.
func requireEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Empty(t, names, "root wrote through the planted link into %s", dir)
}

// As root, init --remote reaches agents/ from / without following a link:
// the engine's user, who may own the config directory, can swap agents/ for
// a symlink, and root must then neither lock, read nor write the credential
// files through it, on the first run or a later one.
func TestInitRemoteAsRootRefusesASymlinkedAgentsDir(t *testing.T) {
	t.Parallel()
	for name, firstRun := range map[string]bool{"first run": true, "later run": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := withState(t, tempConfig(t))
			agents := filepath.Join(filepath.Dir(cfg), "agents")
			if !firstRun {
				remote(t, cfg, "--agent", testAgentKey)
				require.NoError(t, os.RemoveAll(agents))
			}
			elsewhere := t.TempDir()
			require.NoError(t, os.Symlink(elsewhere, agents))

			r := cliNoDB(t, "init", "--remote", "--config", cfg, "--agent", testAgentKey)
			require.Equal(t, exitError, r.code, r.stdout)
			require.Contains(t, r.stderr, "a symlink is refused")
			requireEmptyDir(t, elsewhere)
		})
	}
}

// A credentialFile with .. segments passes the lexical check (it cleans to
// agents/<agent>.url) but would resolve through whatever agents/sub is. As
// root, init --remote uses the path it computed, never the config's string,
// and writes that path back to the config.
func TestInitRemoteAsRootUsesTheComputedCredentialPath(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	first := seedCredential(t, noDB(t), cfg, testAgentKey, agentDSN(t, supabaseURL, guardmodel.DefaultPrefix, testAgentKey, "0123abcd"))
	want := filepath.Join(filepath.Dir(cfg), "agents", testAgentKey+".url")
	require.Equal(t, want, first.credFile)

	// agents/sub -> outside/inner, so agents/sub/../bot.url resolves to
	// outside/bot.url.
	outside := t.TempDir()
	inner := filepath.Join(outside, "inner")
	require.NoError(t, os.Mkdir(inner, 0o700))
	require.NoError(t, os.Symlink(inner, filepath.Join(filepath.Dir(want), "sub")))
	dotted := filepath.Join(filepath.Dir(want), "sub") + "/../" + testAgentKey + ".url"
	setCredentialFile(t, cfg, dotted)

	// The credential stays where the computed path says: init reads it
	// there, never through agents/sub.
	again := remote(t, cfg, "--agent", testAgentKey)
	require.Equal(t, want, again.credFile, "the config gets the computed path back")
	requireEmptyDir(t, inner)
	entries, err := os.ReadDir(outside)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only inner/: nothing written next to it")
}

// setCredentialFile rewrites the agent's store.credentialFile in the config at
// cfg, keeping the rest and its mode 0600.
func setCredentialFile(t *testing.T, cfg, path string) {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	agents, ok := doc["agents"].([]any)
	require.True(t, ok)
	agent, ok := agents[0].(map[string]any)
	require.True(t, ok)
	store := agent["store"].(map[string]any)
	store["credentialFile"] = path
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))
}

// basalt engine started as root reads its config with the
// hardened read: a link is not followed and a config writable by group or
// others is refused, before the engine starts. Not as root, the plain read
// is unchanged.
func TestEngineAsRootUsesTheHardenedConfigRead(t *testing.T) {
	t.Parallel()
	// Not a config at all: the plain read gets as far as parsing it and
	// fails there, so a refusal before reading proves the hardened read.
	const notJSON = "not a config\n"
	run := func(t *testing.T, euid int, path string) (int, string) {
		t.Helper()
		h := newFakeHost(t)
		h.euid = euid
		var stdout, stderr bytes.Buffer
		code := runEngineOn(context.Background(), []string{"--config", path},
			stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, h)
		return code, stderr.String()
	}
	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		other := filepath.Join(t.TempDir(), "engine.json")
		require.NoError(t, os.WriteFile(other, []byte(notJSON), 0o600))
		link := filepath.Join(dir, "engine.json")
		require.NoError(t, os.Symlink(other, link))
		code, stderr := run(t, 0, link)
		require.NotEqual(t, exitOK, code)
		require.Contains(t, stderr, "a symlink, which is refused")
		code, stderr = run(t, 501, link)
		require.NotEqual(t, exitOK, code)
		require.Contains(t, stderr, "invalid character", "not as root, the plain read follows the link")
	})
	t.Run("writable by others", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "engine.json")
		require.NoError(t, os.WriteFile(path, []byte(notJSON), 0o600))
		require.NoError(t, os.Chmod(path, 0o666))
		code, stderr := run(t, 0, path)
		require.NotEqual(t, exitOK, code)
		require.Contains(t, stderr, "writable by group or others")
	})
}

// The whole path of a password rotation on a bot server: root's basalt init
// --remote writes the .pending credential, the person runs the code, and
// the engine, started on that config as the owner of the config directory
// (the service user; this test's user), promotes the .pending credential
// and clears the setup from engine.json. Root hands every file it writes
// there to that owner, so the engine can read, lock and replace them.
func TestEngineFinishesARootInitRotation(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	dir, err := os.MkdirTemp("", "brot") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "basalt", "engine.json")
	install := installed(t, d, dbURL, cfg, "public.leads")
	// The database refuses the bot's credential: a new password.
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	d.Exec(t, `ALTER ROLE `+pgx.Identifier{role}.Sanitize()+` PASSWORD 'not-the-bots'`)
	clearSetup(t, cfg)
	rotate := remoteDBRun(t, cfg, "--agent", "bot")
	require.Equal(t, "AGENT", rotate.res.Kind)
	pending := install.credFile + pendingSuffix
	newPassword := credentialPassword(t, pending)
	runViaConnect(t, d, rotate.res.Code)

	// Sockets the test can make and no pages server; the rest as root
	// wrote it.
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["socketDir"], doc["pagesAddr"] = filepath.Join(dir, "run"), "off"
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfg, raw))

	require.FileExists(t, pending, "nothing promoted it before the engine")
	before, err := config.Load(cfg)
	require.NoError(t, err)
	require.NotNil(t, before.Agents[0].Setup)
	g := olderGuard{d: d, configPath: cfg, socketDir: filepath.Join(dir, "run")}
	g.startEngine(t)
	g.callTool(t, toolStatus)
	require.NoFileExists(t, pending, "promoted")
	require.Equal(t, newPassword, credentialPassword(t, install.credFile))
	c, err := config.Load(cfg)
	require.NoError(t, err)
	require.Nil(t, c.Agents[0].Setup, "the setup is cleared from engine.json")
}
