package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
)

// localInit runs basalt init on the person's machine with the fake host.
// The environment holds an agent marker and an admin connection string;
// init must read neither the string nor stdin.
func localInit(t *testing.T, h *fakeHost, args ...string) (result, []string) {
	t.Helper()
	return localInitWithin(t, time.Minute, h, args...)
}

// localInitWithin is localInit that gives up after limit.
func localInitWithin(t *testing.T, limit time.Duration, h *fakeHost, args ...string) (result, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	var stdout, stderr bytes.Buffer
	var read []string
	getenv := func(k string) string {
		read = append(read, k)
		switch k {
		case "CLAUDECODE":
			return "1"
		case envAdminURL:
			return "postgres://admin" + ":" + "pw@db.example/app"
		}
		return ""
	}
	c := newIO(ctx, stdio{in: strings.NewReader("y\ny\ny\n"), out: &stdout, err: &stderr}, getenv)
	c.goos, c.host, c.interactive = "linux", h, true
	code := runInit(c, args)
	return result{code, stdout.String(), stderr.String()}, read
}

func me752(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	return u.Username
}

// linkJob decodes the job of a setup link.
func linkJob(t *testing.T, link string) localsetup.Job {
	t.Helper()
	_, frag, ok := strings.Cut(link, "#1.")
	require.True(t, ok, link)
	raw, err := base64.RawURLEncoding.DecodeString(frag)
	require.NoError(t, err)
	var j localsetup.Job
	require.NoError(t, json.Unmarshal(raw, &j))
	return j
}

func TestInitInstallsThroughTheDialogThenPrintsAndOpensTheLink(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	// The engine is still starting, then waits for its config.
	h.setupErrs = []error{errors.New("connection refused"), errors.New("connection refused")}
	r, read := localInit(t, h, "--demo")
	require.Equal(t, exitOK, r.code, r.stderr)

	script, err := service.InstallScript("linux", fakeBin)
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog")
	require.Empty(t, h.sudo, "no sudo")
	require.Equal(t, 3, h.setupCalls, "init waited for the setup page")

	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	require.Len(t, lines, 2, "stdout is the link and the MCP line, nothing else")
	require.True(t, strings.HasPrefix(lines[0], "http://localhost:8787/setup/#1."), lines[0])
	require.Equal(t, "basalt mcp --agent demo_bot", lines[1])
	require.Equal(t, localsetup.Job{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: me752(t), Demo: true}, linkJob(t, lines[0]))
	require.Equal(t, []string{lines[0]}, h.opened, "init opens its own link")

	require.NotContains(t, read, envAdminURL, "init never reads the admin connection string")
	require.NotContains(t, r.stderr, "[Y/n]", "init asks nothing in the terminal")
	require.NotContains(t, r.stderr, "Admin connection string")
	require.NotContains(t, r.stdout+r.stderr, "pw@db.example")
}

func TestInitWithTheServiceInstalledAsksNoPassword(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{service.UnitPath("linux"): true}
	r, _ := localInit(t, h, "--demo", "--agent", "sales_bot")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.dialogs)
	require.Equal(t, "sales_bot", linkJob(t, strings.SplitN(r.stdout, "\n", 2)[0]).Agent)
}

func TestInitOnASetUpEngineOpensTheChangeLink(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"--demo"}, {"--agent", "sales_bot"}} {
		h := newFakeHost(t)
		h.sys.existing = map[string]bool{service.UnitPath("linux"): true}
		h.setupCodes = []string{localsetup.CodeJobUnavailable}
		r, read := localInit(t, h, args...)
		require.Equal(t, exitOK, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, h.dialogs, "no password: the service is there")
		lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
		require.Len(t, lines, 1, "stdout is the link only: the agent is registered already")
		agent := "demo_bot"
		if len(args) == 2 {
			agent = args[1]
		}
		require.Equal(t, localsetup.Job{Job: localsetup.JobChange, Agent: agent, OSUser: me752(t)}, linkJob(t, lines[0]), "%v", args)
		require.Equal(t, []string{lines[0]}, h.opened, "init opens its own link")
		require.Contains(t, r.stderr, "update the guard or remove BasaltDB")
		require.NotContains(t, read, envAdminURL)
	}
}

func TestInitStopsBeforeTheDialog(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		name string
		args []string
		edit func(*fakeHost)
		code int
		want string
	}{
		{"an admin-flow flag", []string{"--demo", "--write", "public.leads"}, nil, exitUsage, "takes only --agent and --demo"},
		{"the old --yes", []string{"--demo", "--yes"}, nil, exitUsage, "takes only --agent and --demo"},
		{"no sample database", nil, nil, exitUsage, "basalt init --demo"},
		{"a bad agent name", []string{"--demo", "--agent", "Bad-Name"}, nil, exitUsage, "is not a name an agent can have"},
		{"root", []string{"--demo"}, func(h *fakeHost) { h.euid = 0 }, exitUsage, "not root"},
		{"no dialog", []string{"--demo"}, func(h *fakeHost) { h.noDialog = fmt.Errorf("%w (/usr/bin/pkexec is missing)", service.ErrNoDialog) }, exitError, "cannot be shown here"},
	} {
		h := newFakeHost(t)
		if v.edit != nil {
			v.edit(h)
		}
		r, read := localInit(t, h, v.args...)
		require.Equal(t, v.code, r.code, v.name+": "+r.stderr)
		require.Contains(t, r.stderr, v.want, v.name)
		require.Empty(t, h.dialogs, v.name)
		require.Empty(t, h.sudo, v.name)
		require.Empty(t, r.stdout, v.name)
		require.NotContains(t, read, envAdminURL, v.name)
	}
}

func TestInitSaysWhenTheEngineNeverAnswers(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{service.UnitPath("linux"): true}
	errs := make([]error, 1000)
	for i := range errs {
		errs[i] = errors.New("connection refused")
	}
	h.setupErrs = errs
	r, _ := localInitWithin(t, time.Second, h, "--demo")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "did not answer on http://localhost:8787")
	require.Empty(t, r.stdout)
}
