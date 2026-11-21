package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The code carries the bot's engine key; the person's computer records it
// in the setup's transaction (M4.1, CO-18).
func TestInitSetupCodeRecordsTheEngine(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "engine.json")
	install := remoteAsUser(t, h, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--database-url", dbURL)
	require.NotNil(t, install.payload.Engine, "the code carries the engine key: %s", install.stderr)
	key, err := install.payload.Engine.Key()
	require.NoError(t, err)
	id := channel.EngineIDOf(key)

	_, reg := portalPasskey(t, dbName(t, d))
	r := laptopRun(t, d.URL, reg+"\n", time.Time{}, "--setup-code", install.res.Code, "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "This records engine "+channel.FingerprintOf(id)+" for bot.\n")
	require.Less(t, strings.LastIndex(r.stdout, "SELECT basalt_meta.record_engine("), strings.LastIndex(r.stdout, "SELECT basalt_meta.record_setup("))
	require.True(t, strings.HasSuffix(r.stdout, "Tell bot to check its status.\n"), r.stdout)

	engines, err := guard.Engines(context.Background(), d.Admin, true)
	require.NoError(t, err)
	require.Len(t, engines, 1)
	require.Equal(t, id, engines[0].ID)

	// Another engine recorded in the database is left as it is.
	other := recordTestEngine(t, d)
	change := remoteAsUser(t, h, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	r = laptopRun(t, d.URL, "y\n", time.Time{}, "--setup-code", change.res.Code)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, channel.FingerprintOf(other))
	var revokedAt *time.Time
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT revoked_at FROM basalt_meta.engines WHERE engine_id = $1`, other).Scan(&revokedAt))
	require.Nil(t, revokedAt)

	// A revoked engine is refused, nothing changed, and the next code
	// warns before trusting a server again.
	_, err = guard.RevokeEngine(context.Background(), d.Admin, id)
	require.NoError(t, err)
	again := remoteAsUser(t, h, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	r = laptopRun(t, d.URL, "", time.Time{}, "--setup-code", again.res.Code, "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "ENGINE_REVOKED: engine "+channel.FingerprintOf(id)+" was revoked in this database on ")
	require.Contains(t, r.stderr, "set the engine up again from the start")
}

// remoteAsUser is basalt init --remote run by the engine's own OS user (not
// root), who can make and read the engine's key file.
func remoteAsUser(t *testing.T, h *fakeHost, cfg string, args ...string) remoteRun {
	t.Helper()
	run := func(t *testing.T, args ...string) result {
		t.Helper()
		return cliOn(t, h, map[string]string{envAdminURL: "postgres://admin:adminsecret@db.example.com/postgres"}, "", args...)
	}
	return remoteWith(t, run, cfg, args...)
}

// As root, init reads or makes the engine's key file through the state
// directory it opened (the engine's user owns both in service mode): the
// code carries the engine key, the file is the state directory owner's,
// and a second run carries the same key.
func TestInitRemoteAsRootCarriesTheEngineKey(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	args := []string{"--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app"}
	// The service manager makes the state directory, not init.
	noState := remote(t, cfg, args...)
	require.Nil(t, noState.payload.Engine)
	// A config outside the default place keeps its state next to it, which
	// no service manager makes: init says how to make it.
	require.Contains(t, noState.stderr, "does not exist yet; make it for the engine's user (sudo install -d -m 0700 -o ")
	require.NoDirExists(t, noState.cfg.StateDirFor(runtime.GOOS))
	require.NoError(t, os.Mkdir(noState.cfg.StateDirFor(runtime.GOOS), 0o700))

	install := remote(t, cfg, append(args, "--new-code")...)
	require.NotNil(t, install.payload.Engine, install.stderr)
	require.NotContains(t, install.stderr, "carries no engine key")
	keyFile := filepath.Join(install.cfg.StateDirFor(runtime.GOOS), channel.KeyFileName)
	keys, err := channel.LoadKeys(keyFile)
	require.NoError(t, err, "the engine loads the key file root made")
	require.Equal(t, base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI()), install.payload.Engine.PublicKey)

	again := remote(t, cfg, append(args, "--new-code")...)
	require.Equal(t, install.payload.Engine, again.payload.Engine)

	// A key file the engine's user replaced with a symlink is refused, and
	// the code carries no key.
	require.NoError(t, os.Rename(keyFile, keyFile+".moved"))
	require.NoError(t, os.Symlink(keyFile+".moved", keyFile))
	refused := remote(t, cfg, append(args, "--new-code")...)
	require.Nil(t, refused.payload.Engine)
	require.Contains(t, refused.stderr, "is a symlink, which is refused")
}

// The state directory comes from engine.json, which the config directory's
// owner may write: as root, init reads or makes a key file only in a state
// directory that owner owns, and never makes one.
func TestInitRemoteAsRootKeepsTheKeyToTheConfigOwnersStateDirectory(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	args := append(make([]string, 0, 8), "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	remote(t, cfg, args...)
	raw, err := os.ReadFile(cfg)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	missing := filepath.Join(t.TempDir(), "x", "y")
	for _, stateDir := range []string{"/usr", missing} {
		doc["stateDir"] = stateDir
		out, err := json.MarshalIndent(doc, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(cfg, out, 0o600))
		r := remote(t, cfg, append(args, "--new-code")...)
		require.Nil(t, r.payload.Engine, stateDir)
		require.Contains(t, r.stderr, "the code carries no engine key", stateDir)
	}
	require.NoFileExists(t, filepath.Join("/usr", channel.KeyFileName))
	require.NoDirExists(t, filepath.Dir(missing), "nothing is made on the way")
}
