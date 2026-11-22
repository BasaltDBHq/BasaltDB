package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// fakeAgentDSN stands in for the agent's connection string, which goes to
// sudo on stdin and never into the dialog.
const fakeAgentDSN = "the-agent-connection-string"

// dialogInit runs basalt init with an admin connection nothing answers on:
// a stop before the database is reached never shows "connect:".
func dialogInit(t *testing.T, h *fakeHost, goos string, extra ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	getenv := func(k string) string {
		if k == envAdminURL {
			return "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"
		}
		return ""
	}
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, getenv)
	c.goos, c.host = goos, h
	code := runInitAdmin(c, append([]string{"--agent", "bot", "--write", "public.leads", "--skip-passkey", "--yes"}, extra...))
	return result{code, stdout.String(), stderr.String()}
}

// With no administrator dialog (an SSH session, a machine without a
// desktop), init says so and stops before it reaches the database, and
// never falls back to running the engine as the person's user.
func TestInitStopsWithoutAnAdministratorDialog(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		h := newFakeHost(t)
		h.noDialog = fmt.Errorf("%w (/usr/bin/pkexec is missing)", service.ErrNoDialog)
		r := dialogInit(t, h, goos)
		require.Equal(t, exitError, r.code, goos)
		require.Contains(t, r.stderr, "basalt init installs the engine service through the system's administrator dialog, which only you can answer, "+
			"and it cannot be shown here (no administrator dialog is available here (/usr/bin/pkexec is missing)). "+
			"Run basalt init again in a desktop session on this machine; basalt does not run the engine as your user instead")
		require.NotContains(t, r.stderr, "--no-service", "no way around the dialog is offered")
		require.NotContains(t, r.stderr, "connect:", "init never connects")
		require.Empty(t, r.stdout, "no SQL is planned")
		require.Empty(t, h.dialogs)
		require.Empty(t, h.sudo)
	}
}

// The fixed script installs the engine as its default user from the system
// config; anything else is a usage error before the database is reached.
func TestInitFirstInstallTakesOnlyTheDefaultEngineUser(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	r := dialogInit(t, h, "linux", "--engine-user", "someone")
	require.Equal(t, exitUsage, r.code, r.stderr)
	require.Contains(t, r.stderr, "a first install creates the engine's OS user basalt; drop --engine-user")
	require.NotContains(t, r.stderr, "connect:")
	require.Empty(t, h.dialogs)
	require.Empty(t, h.sudo)
}

// dialogFlags are init's flags for a service install on goos.
func dialogFlags(t *testing.T, c *cliIO) initFlags {
	t.Helper()
	f, err := parseInit(c, []string{"--agent", "bot", "--write", "public.leads", "--skip-passkey", "--yes", "--os-user", me(t)})
	require.NoError(t, err)
	return f
}

func dialogIO(h *fakeHost, goos string) *cliIO {
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
	c.goos, c.host = goos, h
	return c
}

func TestElevateInstallAsksTheDialogOnlyOnAFirstInstall(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		// First install: the dialog runs the fixed script, then sudo.
		h := newFakeHost(t)
		c := dialogIO(h, goos)
		require.NoError(t, elevateInstall(c, dialogFlags(t, c), fakeAgentDSN))
		script, err := service.InstallScript(goos, fakeBin)
		require.NoError(t, err)
		require.Equal(t, []string{script}, h.dialogs, goos)
		require.Len(t, h.sudo, 1)

		// The unit is installed: no dialog, sudo as before.
		h = newFakeHost(t)
		h.sys.existing = map[string]bool{service.UnitPath(goos): true}
		c = dialogIO(h, goos)
		require.NoError(t, elevateInstall(c, dialogFlags(t, c), fakeAgentDSN))
		require.Empty(t, h.dialogs, goos)
		require.Len(t, h.sudo, 1)
	}
}

// A dialog the person cancels, or whose script stops, ends the install:
// sudo never runs and the engine is not run as the person's user.
func TestElevateInstallStopsWhenTheDialogDoesNotInstall(t *testing.T) {
	t.Parallel()
	for _, dialogErr := range []error{
		service.ErrDialogCancelled,
		fmt.Errorf("%w: basalt: /etc/basalt is writable by group or others", service.ErrDialogScript),
	} {
		h := newFakeHost(t)
		h.dialogErr = dialogErr
		c := dialogIO(h, "linux")
		err := elevateInstall(c, dialogFlags(t, c), fakeAgentDSN)
		require.ErrorIs(t, err, dialogErr)
		require.True(t, isDialogStop(err))
		require.Len(t, h.dialogs, 1)
		require.Empty(t, h.sudo)
	}

	// No dialog after all (pkexec found no authentication agent): the same
	// stop as before the SQL.
	h := newFakeHost(t)
	h.dialogErr = fmt.Errorf("%w (pkexec: No authentication agent found.)", service.ErrNoDialog)
	c := dialogIO(h, "linux")
	err := elevateInstall(c, dialogFlags(t, c), fakeAgentDSN)
	require.ErrorContains(t, err, "Run basalt init again in a desktop session on this machine")
	require.Empty(t, h.sudo)
}

// The script the dialog runs is the same whatever the agent, the flags,
// the environment and the folder init runs in.
func TestDialogScriptIsTheSameForEveryAgent(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	c := dialogIO(h, "linux")
	require.NoError(t, dialogInstall(c, dialogFlags(t, c)))

	h2 := newFakeHost(t)
	c2 := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}},
		func(k string) string { return "/somewhere/" + k })
	c2.goos, c2.host = "linux", h2
	f, err := parseInit(c2, []string{"--agent", "other", "--write", "public.notes", "--skip-passkey", "--yes", "--os-user", me(t), "--prefix", "other"})
	require.NoError(t, err)
	require.NoError(t, dialogInstall(c2, f))
	require.Equal(t, h.dialogs, h2.dialogs)
	require.NotContains(t, h.dialogs[0], "bot")
}

// An engine set up for a bot keeps sudo alone: its person often has no
// desktop session on the bot's machine.
func TestElevateInstallForABotEngineAsksNoDialog(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	c := dialogIO(h, "linux")
	f, err := parseInit(c, []string{"--agent", "bot", "--write", "public.leads", "--skip-passkey", "--yes", "--os-user", me(t), "--operated-by=agent"})
	require.NoError(t, err)
	require.NoError(t, elevateInstall(c, f, fakeAgentDSN))
	require.Empty(t, h.dialogs)
	require.Len(t, h.sudo, 1)
}

// As root, init installs in this process: no dialog.
func TestElevateInstallAsRootAsksNoDialog(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.euid = 0
	c := dialogIO(h, "linux")
	require.False(t, needsDialog(c, dialogFlags(t, c)))
	require.NoError(t, dialogInstall(c, dialogFlags(t, c)))
	require.Empty(t, h.dialogs)
}
