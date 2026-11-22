package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/internal/connecttest"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// codeFor is basalt init --remote's code for the bot in database d, which
// the person confirmed on the connect page and which does not record the
// setup yet: an INSTALL code with the credential's password, for every
// table in public, which the person ticks.
func codeFor(t *testing.T, d *guardtest.DB, dbURL, cfg string) remoteRun {
	t.Helper()
	pw, err := setupcode.NewPassword()
	require.NoError(t, err)
	seedCredential(t, withDB(t), cfg, "bot", agentDSN(t, dbURL, d.Names.Prefix, "bot", pw))
	return remoteDBRun(t, cfg, "--agent", "bot")
}

// runViaConnect runs code against database d through the connect page, as the
// person does: the passkey is made when the database has none, and ticked
// are the tables left ticked (a code with ticks needs at least one).
func runViaConnect(t *testing.T, d *guardtest.DB, code string, ticked ...string) {
	t.Helper()
	_, base := connecttest.Start(t)
	p := page{t, base}
	var desc connectv1.DescribeSetupResponse
	p.ok("DescribeSetup", map[string]any{"code": code}, &desc)
	body := map[string]any{"code": code, "databaseUrl": d.URL}
	if len(ticked) > 0 {
		body["includedTables"] = ticked
	}
	var chk connectv1.CheckSetupResponse
	p.ok("CheckSetup", map[string]any{"code": code, "databaseUrl": d.URL}, &chk)
	if chk.GetPasskeyNeeded() {
		person, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		body["challenge"] = challengeJSON(desc.GetChallenge())
		body["passkey"] = passkeyOf(t, person, desc.GetChallenge())
	}
	var run connectv1.RunSetupResponse
	p.ok("RunSetup", body, &run)
}

// installed runs an INSTALL code made by basalt init --remote through the
// connect page, with ticked left ticked, and returns the bot's run.
func installed(t *testing.T, d *guardtest.DB, dbURL, cfg string, ticked ...string) remoteRun {
	t.Helper()
	install := codeFor(t, d, dbURL, cfg)
	require.Equal(t, "INSTALL", install.res.Kind)
	runViaConnect(t, d, install.res.Code, ticked...)
	return install
}

// agentLogsIn reports whether the agent's credential file logs in and its
// setup is recorded, as the engine checks when it finishes a setup.
func agentLogsIn(t *testing.T, credFile, setupID string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, credentialDSN(t, credFile))
	if err != nil {
		return false
	}
	defer conn.Close(ctx)
	found, err := guard.SetupRecorded(ctx, conn, uuid.MustParse(setupID))
	require.NoError(t, err)
	return found
}

func credentialDSN(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func installedVersion(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	return v
}

// damaged changes the last character of the code's check.
func damaged(code string) string {
	if strings.HasSuffix(code, "A") {
		return code[:len(code)-1] + "B"
	}
	return code[:len(code)-1] + "A"
}
