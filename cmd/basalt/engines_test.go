package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
)

func recordTestEngine(t *testing.T, d *guardtest.DB) string {
	t.Helper()
	k, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	id, err := guard.RecordEngine(context.Background(), d.Admin, k.PublicKeySPKI())
	require.NoError(t, err)
	return id
}

func TestEngineListAndRevoke(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile := initAgent(t, d, t.TempDir()+"/engine.json")
	admin := map[string]string{envAdminURL: d.URL}
	lost := recordTestEngine(t, d)
	other := recordTestEngine(t, d)

	r := cli(t, nil, "", "engine", "list", "--credential-file", credFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, channel.FingerprintOf(lost)+"  recorded ")
	require.Contains(t, r.stdout, channel.FingerprintOf(other)+"  recorded ")

	// Revoke: a prefix too short, a declined confirmation, and an unknown
	// engine change nothing.
	r = cli(t, admin, "", "engine", "revoke", "--", lost[:4])
	require.Equal(t, exitError, r.code)
	r = cli(t, admin, "n\n", "engine", "revoke", "--", lost[:10])
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "nothing was revoked")
	r = cli(t, admin, "", "engine", "revoke", "--yes", "--", "zzzzzzzzzz")
	require.Equal(t, exitError, r.code)

	// The fingerprint as shown, spaces and all, names the engine.
	r = cli(t, admin, "y\n", "engine", "revoke", "--", channel.FingerprintOf(lost)[:14])
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "engine "+channel.FingerprintOf(lost)+" revoked. 1 engines remain")
	require.Contains(t, r.stderr, "ENGINE_REVOKED")
	require.Empty(t, r.stdout)

	// Already revoked: refused, as an unknown one.
	r = cli(t, admin, "", "engine", "revoke", "--yes", "--", lost)
	require.Equal(t, exitError, r.code)

	// Without an id it asks which, listing only the ones not revoked.
	r = cli(t, admin, other[:9]+"\n", "engine", "revoke", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, channel.FingerprintOf(lost))
	require.Contains(t, r.stderr, "Which engine?")
	r = cli(t, admin, "", "engine", "revoke", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no engine is recorded and not revoked")

	r = cli(t, admin, "", "engine", "list", "--admin", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out []map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Len(t, out, 2)
	for _, e := range out {
		require.ElementsMatch(t, []string{"engineId", "fingerprint", "recordedAt", "revokedAt", "self"}, keysOf(e), "no key material")
		require.NotNil(t, e["revokedAt"])
		require.Equal(t, false, e["self"])
	}
	r = cli(t, nil, "", "engine", "list", "--credential-file", credFile)
	require.Equal(t, 2, strings.Count(r.stdout, " revoked "), r.stdout)

	require.Equal(t, exitUsage, cli(t, nil, "", "engine", "rename").code)
}

func TestEngineListOnAnOlderGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile := initAgent(t, d, t.TempDir()+"/engine.json")
	d.Exec(t, `DROP VIEW basalt_meta.agent_engines`)

	r := cli(t, nil, "", "engine", "list", "--credential-file", credFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "older than version 33")
}
