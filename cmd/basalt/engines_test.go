package main

import (
	"context"
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

func TestEngineRevoke(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	_ = initAgent(t, d, t.TempDir()+"/engine.json")
	admin := map[string]string{envAdminURL: d.URL}
	lost := recordTestEngine(t, d)
	other := recordTestEngine(t, d)

	// Revoke: a prefix too short, a declined confirmation, and an unknown
	// engine change nothing.
	r := cli(t, admin, "", "engine", "revoke", "--", lost[:4])
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

	require.Equal(t, exitUsage, cli(t, nil, "", "engine", "rename").code)
}
