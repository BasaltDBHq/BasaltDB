package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// interruptedInit runs a first init that creates the agent's role, then
// removes its credential file, as when a run stops before the engine is set
// up. It returns the old credential.
func interruptedInit(t *testing.T, d *guardtest.DB, h *fakeHost) string {
	t.Helper()
	r := initRun(t, d, h, "linux", false, "", "--yes", "--no-service")
	require.Equal(t, exitOK, r.code, r.stderr)
	cred := filepath.Join(h.configDir, perUserDirName, "agents", "bot.url")
	b, err := os.ReadFile(cred)
	require.NoError(t, err)
	require.NoError(t, os.Remove(cred))
	return strings.TrimSpace(string(b))
}

func logsIn(t *testing.T, dsn string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	if err != nil {
		return false
	}
	conn.Close(ctx)
	return true
}

func TestInitRerunWithoutCredentialSetsANewPassword(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	old := interruptedInit(t, d, h)

	// Answers: set a new password (default), run the SQL, no service.
	r := initRun(t, d, h, "linux", true, "\ny\nn\n")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "role "+d.Names.Prefix+"_agent_bot exists but its credential file")
	require.Contains(t, r.stderr, "Set a new password for it and write the credential? [Y/n]")
	b, err := os.ReadFile(filepath.Join(h.configDir, perUserDirName, "agents", "bot.url"))
	require.NoError(t, err, "the credential is written again")
	require.True(t, logsIn(t, strings.TrimSpace(string(b))), "the new credential logs in")
	require.False(t, logsIn(t, old), "the old password no longer works")
}

func TestInitRerunWithoutCredentialYesInstallsTheService(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	interruptedInit(t, d, h)

	r := initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "[Y/n]", "--yes asks nothing")
	require.Len(t, h.sudo, 1)
	require.Equal(t, "--credential-stdin", h.sudo[0][len(h.sudo[0])-1], "a new credential, not the kept one")
	require.True(t, logsIn(t, strings.TrimSpace(h.sudoIn[0])))
}

func TestInitRerunWithoutCredentialRefusedKeepsThePassword(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	old := interruptedInit(t, d, h)

	r := initRun(t, d, h, "linux", true, "n\n")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "--rotate-password")
	require.True(t, logsIn(t, old), "a no keeps the password")

	// Without a terminal and without --yes, init does not decide for the person.
	r = initRun(t, d, h, "linux", false, "", "--no-service")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "pass --yes")
	require.True(t, logsIn(t, old), "nothing changed")
}
