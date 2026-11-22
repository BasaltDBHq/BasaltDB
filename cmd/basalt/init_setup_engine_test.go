package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The code carries the bot's engine key; the person's computer records it
// in the setup's transaction (M4.1, CO-18).
func TestInitSetupCodeRecordsTheEngine(t *testing.T) {
	t.Parallel()
	d, dbURL := remoteDB(t)
	h := newFakeHost(t)
	cfg := filepath.Join(h.configDir, "engine.json")
	seedDB(t, remoteEnv{host: h}, cfg, d, dbURL, "0123abcd")
	install := remoteAsUser(t, h, cfg)
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
	change := remoteAsUser(t, h, cfg)
	require.NotEqual(t, install.res.SetupID, change.res.SetupID)
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
	again := remoteAsUser(t, h, cfg)
	r = laptopRun(t, d.URL, "", time.Time{}, "--setup-code", again.res.Code, "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "ENGINE_REVOKED: engine "+channel.FingerprintOf(id)+" was revoked in this database on ")
	require.Contains(t, r.stderr, "set the engine up again from the start")
}

// remoteAsUser is basalt init --remote for the bot run by the engine's own
// OS user (not root), who can make and read the engine's key file.
func remoteAsUser(t *testing.T, h *fakeHost, cfg string) remoteRun {
	t.Helper()
	return remoteWith(t, remoteEnv{host: h}, cfg, "--agent", "bot")
}

// As root, init reads or makes the engine's key file through the state
// directory it opened (the engine's user owns both in service mode): the
// code carries the engine key, the file is the state directory owner's,
// and a second run carries the same key.
func TestInitRemoteAsRootCarriesTheEngineKey(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	loaded, err := config.Load(cfg)
	require.NoError(t, err)
	stateDir := loaded.StateDirFor(runtime.GOOS)
	keyFile := filepath.Join(stateDir, channel.KeyFileName)

	install := remote(t, cfg, "--agent", "bot")
	require.NotNil(t, install.payload.Target, "a code for the credential's database")
	require.NotNil(t, install.payload.Engine, install.stderr)
	require.NotContains(t, install.stderr, "carries no engine key")
	keys, err := channel.LoadKeys(keyFile)
	require.NoError(t, err, "the engine loads the key file root made")
	require.Equal(t, base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI()), install.payload.Engine.PublicKey)

	clearSetup(t, cfg)
	again := remote(t, cfg, "--agent", "bot")
	require.Equal(t, install.payload.Engine, again.payload.Engine)

	// A key file the engine's user replaced with a symlink is refused, and
	// the code carries no key.
	clearSetup(t, cfg)
	require.NoError(t, os.Rename(keyFile, keyFile+".moved"))
	require.NoError(t, os.Symlink(keyFile+".moved", keyFile))
	refused := remote(t, cfg, "--agent", "bot")
	require.Nil(t, refused.payload.Engine)
	require.Contains(t, refused.stderr, "is a symlink, which is refused")

	// The service manager makes the state directory, not init. A config
	// outside the default place keeps its state next to it, which no
	// service manager makes: init says how to make it.
	clearSetup(t, cfg)
	require.NoError(t, os.RemoveAll(stateDir))
	noState := remote(t, cfg, "--agent", "bot")
	require.Nil(t, noState.payload.Engine)
	require.Contains(t, noState.stderr, "does not exist yet; make it for the engine's user (sudo install -d -m 0700 -o ")
	require.NoDirExists(t, stateDir)
}

// The state directory comes from engine.json, which the config directory's
// owner may write: as root, init reads or makes a key file only in a state
// directory that owner owns, and never makes one.
func TestInitRemoteAsRootKeepsTheKeyToTheConfigOwnersStateDirectory(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	installedAgent(t, noDB(t), cfg, supabaseDSN(t))
	missing := filepath.Join(t.TempDir(), "x", "y")
	for _, stateDir := range []string{"/usr", missing} {
		editConfig(t, cfg, func(c *config.Config) { c.StateDir = stateDir; c.Agents[0].Setup = nil })
		r := remote(t, cfg, "--agent", "bot")
		require.Nil(t, r.payload.Engine, stateDir)
		require.Contains(t, r.stderr, "the code carries no engine key", stateDir)
	}
	require.NoFileExists(t, filepath.Join("/usr", channel.KeyFileName))
	require.NoDirExists(t, filepath.Dir(missing), "nothing is made on the way")
}
