package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// The code carries the bot's engine key; the person's computer records it
// with the address they give, in the setup's transaction (M4.1, CO-18).
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

	// A bad address is a usage error before anything else.
	r := laptopRun(t, d.URL, "", time.Time{}, "--setup-code", install.res.Code, "--yes", "--engine-url", "https://localhost")
	require.Equal(t, exitUsage, r.code, r.stderr)

	_, reg := portalPasskey(t, dbName(t, d))
	r = laptopRun(t, d.URL, reg+"\n", time.Time{}, "--setup-code", install.res.Code, "--yes", "--engine-url", "https://engine.example.com/")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "This records engine "+channel.FingerprintOf(id)+" for bot. Its address: https://engine.example.com.")
	require.Less(t, strings.LastIndex(r.stdout, "SELECT basalt_meta.record_engine("), strings.LastIndex(r.stdout, "SELECT basalt_meta.record_setup("))
	require.True(t, strings.HasSuffix(r.stdout, "Pin it on each device you approve from:\n"+pinAddURL+"\n"), r.stdout)

	engines, err := guard.Engines(context.Background(), d.Admin, true)
	require.NoError(t, err)
	require.Len(t, engines, 1)
	require.Equal(t, id, engines[0].ID)
	require.Equal(t, "https://engine.example.com", *engines[0].URL)

	// Another engine at the same address: asked, and revoked on yes, with
	// the new one recorded, in one transaction.
	addr := "https://engine.example.com"
	other := recordTestEngine(t, d, &addr)
	change := remoteAsUser(t, h, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	r = laptopRun(t, d.URL, "y\ny\n", time.Time{}, "--setup-code", change.res.Code, "--engine-url", "https://engine.example.com")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "Engine "+channel.FingerprintOf(other)+" is also recorded at https://engine.example.com")
	var revokedAt *time.Time
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT revoked_at FROM basalt_meta.engines WHERE engine_id = $1`, other).Scan(&revokedAt))
	require.NotNil(t, revokedAt, "the person said yes")

	// A revoked engine is refused, nothing changed, and the next code
	// warns before trusting a server again.
	_, err = guard.RevokeEngine(context.Background(), d.Admin, id)
	require.NoError(t, err)
	again := remoteAsUser(t, h, cfg, "--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--new-code")
	r = laptopRun(t, d.URL, "", time.Time{}, "--setup-code", again.res.Code, "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "ENGINE_REVOKED: engine "+channel.FingerprintOf(id)+" was revoked in this database on ")
	require.Contains(t, r.stderr, "basalt engine rotate-key")
}

// --engine-url needs a code that carries the engine key.
func TestInitSetupCodeEngineURLNeedsAKey(t *testing.T) {
	t.Parallel()
	cfg := tempConfig(t)
	install := remote(t, cfg, "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	p := install.payload
	p.Engine = nil
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	r := laptopRun(t, "postgres://admin@127.0.0.1:1/app", "", time.Time{}, "--setup-code", code, "--yes", "--engine-url", "https://engine.example.com")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "ENGINE_KEY_MISSING: this setup code carries no engine key")
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

// As root, init cannot make a key file the engine's user owns: the code
// carries no engine key, and init says how to get one.
func TestInitRemoteAsRootCarriesNoEngineKey(t *testing.T) {
	t.Parallel()
	install := remote(t, tempConfig(t), "--agent", "bot", "--write", "public.leads", "--database-url", "postgres://u@db.example.com:5432/app")
	require.Nil(t, install.payload.Engine)
	require.Contains(t, install.stderr, "the code carries no engine key: run basalt init --remote as")
}
