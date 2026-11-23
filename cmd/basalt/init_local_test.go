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

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
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
	c := newIO(ctx, cli.Stdio{In: strings.NewReader("y\ny\ny\n"), Out: &stdout, Err: &stderr}, getenv)
	c.goos, c.host, c.interactive = "linux", h, true
	code := runInit(c, appSetupHost{}, args)
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
	require.Equal(t, cli.ExitOK, r.code, r.stderr)

	script, err := osservice.InstallScript("linux", fakeBin)
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog")
	require.Equal(t, []string{servicespec.InstallPrompt}, h.prompts, "the dialog names the install")
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

// Without --demo the link opens the page's install of the person's own
// tables: the same dialog, link and MCP line, with demo false.
func TestInitWithoutDemoOpensTheInstallOfARealDatabase(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	r, read := localInit(t, h, "--agent", "sales_bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.dialogs, 1, "the engine service is installed through the dialog, as for --demo")
	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	require.Len(t, lines, 2, r.stdout)
	require.Equal(t, localsetup.Job{Job: localsetup.JobInstall, Agent: "sales_bot", OSUser: me752(t), Demo: false}, linkJob(t, lines[0]))
	require.Equal(t, "basalt mcp --agent sales_bot", lines[1])
	require.Equal(t, []string{lines[0]}, h.opened)
	require.NotContains(t, read, envAdminURL)
}

func TestInitWithTheServiceInstalledAsksNoPassword(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	r, _ := localInit(t, h, "--demo", "--agent", "sales_bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Empty(t, h.dialogs)
	require.Equal(t, "sales_bot", linkJob(t, strings.SplitN(r.stdout, "\n", 2)[0]).Agent)
}

func TestInitOnASetUpEngineOpensTheChangeLink(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"--demo"}, {"--agent", "sales_bot"}} {
		h := newFakeHost(t)
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{localsetup.CodeJobUnavailable}
		r, read := localInitWithin(t, 2*time.Second, h, args...)
		require.Equal(t, cli.ExitOK, r.code, "%v: %s", args, r.stderr)
		require.Contains(t, r.stderr, "after a Remove on that page, run basalt init once more", "no Remove within the wait: init returns, and removes nothing")
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
		{"an admin-flow flag", []string{"--demo", "--write", "public.leads"}, nil, cli.ExitUsage, "takes only --agent and --demo"},
		{"the old --yes", []string{"--demo", "--yes"}, nil, cli.ExitUsage, "takes only --agent and --demo"},
		{"a bad agent name", []string{"--demo", "--agent", "Bad-Name"}, nil, cli.ExitUsage, "is not a name an agent can have"},
		{"root", []string{"--demo"}, func(h *fakeHost) { h.euid = 0 }, cli.ExitUsage, "not root"},
		{"no dialog", []string{"--demo"}, func(h *fakeHost) { h.noDialog = fmt.Errorf("%w (/usr/bin/pkexec is missing)", servicespec.ErrNoDialog) }, cli.ExitError, "cannot be shown here"},
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
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	errs := make([]error, 1000)
	for i := range errs {
		errs[i] = errors.New("connection refused")
	}
	h.setupErrs = errs
	r, _ := localInitWithin(t, time.Second, h, "--demo")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "did not answer on http://localhost:8787")
	require.Empty(t, r.stdout)
}

// An engine service the service manager starts again during the wait,
// after it exited with an error, ends the wait at once, naming its log. One
// that started once and never exited, or whose crashes are all older than
// the wait, is waited for.
func TestInitSaysWhenTheEngineServiceKeepsStopping(t *testing.T) {
	t.Parallel()
	refused := func() []error {
		errs := make([]error, 1000)
		for i := range errs {
			errs[i] = errors.New("connection refused")
		}
		return errs
	}
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{3, 3, 4}, 1
	start := time.Now()
	r, _ := localInitWithin(t, 5*time.Second, h, "--demo")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "the engine service keeps stopping: it started 4 times and last exited with code 1")
	require.Contains(t, r.stderr, "journalctl -u "+servicespec.SystemdUnitName)
	require.Less(t, time.Since(start), 2*time.Second, "no wait for the setup page's whole bound")
	require.Empty(t, r.stdout)

	h = newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{1}, -1
	r, _ = localInitWithin(t, time.Second, h, "--demo")
	require.Contains(t, r.stderr, "did not answer on", "one run that never exited is still starting")

	h = newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{5}, 1
	r, _ = localInitWithin(t, time.Second, h, "--demo")
	require.Contains(t, r.stderr, "did not answer on", "crashes from before this wait are not this wait's")
}

func TestServiceRunsParse(t *testing.T) {
	t.Parallel()
	runs, last, err := parseLaunchdRuns("system/dev.basaltdb.engine = {\n\tactive count = 0\n\tstate = spawn scheduled\n\truns = 4\n\tlast exit code = 1\n}\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{4, 1}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 2\n\tlast exit code = 78: EX_CONFIG\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{2, 78}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 3\n\tlast exit code = 1: Operation not permitted\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{3, 1}, [2]int{runs, last})
	runs, last, err = parseLaunchdRuns("\truns = 1\n\tlast exit code = (never exited)\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{1, -1}, [2]int{runs, last})
	_, _, err = parseLaunchdRuns("Bad request.\n")
	require.Error(t, err)

	runs, last, err = parseSystemdRuns("NRestarts=3\nExecMainStatus=1\n")
	require.NoError(t, err)
	require.Equal(t, [2]int{4, 1}, [2]int{runs, last})
	_, _, err = parseSystemdRuns("")
	require.Error(t, err)

	require.True(t, crashLoops(2, 1))
	require.False(t, crashLoops(1, 1), "the first exit: the service manager has not started it again yet")
	require.False(t, crashLoops(3, 0), "a clean exit, a restart")
	require.False(t, crashLoops(1, -1))
}

// After the page's Remove deleted engine.json, basalt init (which the agent
// runs once more, as the page and its next steps say) goes straight to the
// administrator dialog with the fixed removal script: no link.
func TestInitOnARemovedEngineRemovesTheService(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{localsetup.CodeEngineRemoved}
	r, read := localInit(t, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Empty(t, h.opened)
	require.Empty(t, r.stdout)
	script, err := osservice.RemoveScript("linux")
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog")
	require.Equal(t, []string{servicespec.RemovePrompt}, h.prompts, "the dialog names the removal")
	require.Empty(t, h.sudo)
	require.Contains(t, r.stderr, "the engine service is removed")
	require.NotContains(t, read, envAdminURL)
}

func TestInitRemovalStops(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		name string
		edit func(*fakeHost)
		want string
	}{
		{"dialog closed", func(h *fakeHost) { h.dialogErr = servicespec.ErrDialogCancelled }, "the administrator dialog was closed, so the engine service stays. Run basalt init again"},
		{"no dialog", func(h *fakeHost) { h.noDialog = fmt.Errorf("%w (an SSH session)", servicespec.ErrNoDialog) }, "cannot be shown here"},
		{"script stopped", func(h *fakeHost) { h.dialogErr = fmt.Errorf("%w: engine.json still exists", osservice.ErrDialogScript) }, "the engine service was not removed"},
	} {
		h := newFakeHost(t)
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{localsetup.CodeEngineRemoved}
		v.edit(h)
		r, _ := localInit(t, h)
		require.Equal(t, cli.ExitError, r.code, v.name)
		require.Contains(t, r.stderr, v.want, v.name)
	}
}

// A Remove on the page within the wait: the init that opened the link goes
// straight on to the administrator dialog and the removal script.
func TestInitRemovesTheServiceWhenTheRemoveLandsWithinTheWait(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{localsetup.CodeJobUnavailable, localsetup.CodeJobUnavailable, localsetup.CodeEngineRemoved}
	r, _ := localInit(t, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.opened, 1, "init opened the Update/Remove link first")
	script, err := osservice.RemoveScript("linux")
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs)
	require.Contains(t, r.stderr, "the engine service is removed")
}

// "No, this isn't mine" on the page within the wait (Not your database):
// the init that opened the Update check resets the engine through the
// administrator dialog with the fixed reset script, then opens the install
// link once the engine waits for a first install.
func TestInitResetsThroughTheDialogThenOpensTheInstallLink(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{
		localsetup.CodeJobUnavailable, localsetup.CodeJobUnavailable, localsetup.CodeResetAsked, localsetup.CodeInvalidArgument,
	}
	r, read := localInit(t, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	script, err := osservice.ResetScript("linux")
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog, for the fixed reset script")
	require.Equal(t, []string{servicespec.ResetPrompt}, h.prompts, "the dialog names the reset")
	require.Empty(t, h.sudo)
	require.Len(t, h.opened, 2, "the Update check's link, then the install link")
	require.Equal(t, localsetup.Job{Job: localsetup.JobChange, Agent: "demo_bot", OSUser: me752(t)}, linkJob(t, h.opened[0]))
	require.Equal(t, localsetup.Job{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: me752(t)}, linkJob(t, h.opened[1]))
	require.Contains(t, r.stderr, "BasaltDB on this computer is reset")
	require.Contains(t, r.stdout, "basalt mcp --agent demo_bot")
	require.NotContains(t, read, envAdminURL)
}

// Without the dialog, or with it closed, nothing is reset and no install
// link opens; a "No" found at the start resets nothing either.
func TestInitResetStops(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		name string
		edit func(*fakeHost)
		want string
	}{
		{"no dialog", func(h *fakeHost) { h.noDialog = fmt.Errorf("%w (an SSH session)", servicespec.ErrNoDialog) }, "cannot be shown here"},
		{"dialog closed", func(h *fakeHost) { h.dialogErr = servicespec.ErrDialogCancelled }, "the administrator dialog was closed, so nothing was reset"},
		{"script stopped", func(h *fakeHost) { h.dialogErr = fmt.Errorf("%w: no setup to reset", osservice.ErrDialogScript) }, "was not reset"},
	} {
		h := newFakeHost(t)
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{localsetup.CodeJobUnavailable, localsetup.CodeResetAsked}
		v.edit(h)
		r, _ := localInit(t, h)
		require.Equal(t, cli.ExitError, r.code, v.name)
		require.Contains(t, r.stderr, v.want, v.name)
		require.Len(t, h.opened, 1, "%s: no install link", v.name)
		if v.name == "no dialog" {
			require.Empty(t, h.dialogs)
		}
	}

	h := newFakeHost(t)
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{localsetup.CodeResetAsked, localsetup.CodeJobUnavailable}
	r, _ := localInitWithin(t, 3*time.Second, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Empty(t, h.dialogs, "a No left from an earlier page resets nothing")
	require.Len(t, h.opened, 1)
	require.Equal(t, localsetup.JobChange, linkJob(t, h.opened[0]).Job)
}

func TestInitWaitsAsLongAsAnApprovalWait(t *testing.T) {
	t.Parallel()
	require.Equal(t, 90*time.Second, removalWait)
}

// Plain basalt init never reads BASALT_ADMIN_DATABASE_URL, with or without
// an agent marker and with or without a terminal: the admin connection
// string is typed on the setup page only.
func TestPlainInitNeverReadsTheAdminEnv(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		marker      bool
		interactive bool
	}{{"a person at a terminal", false, true}, {"no terminal", false, false}, {"an agent marker", true, true}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		var stdout, stderr bytes.Buffer
		var read []string
		getenv := func(k string) string {
			read = append(read, k)
			switch {
			case k == envAdminURL:
				return "postgres://admin" + ":" + "pw@db.example/app"
			case k == "CLAUDECODE" && tc.marker:
				return "1"
			}
			return ""
		}
		c := newIO(ctx, cli.Stdio{In: strings.NewReader(leakedAdmin + "\n"), Out: &stdout, Err: &stderr}, getenv)
		c.goos, c.host, c.interactive = "linux", newFakeHost(t), tc.interactive
		code := runInit(c, appSetupHost{}, []string{"--demo"})
		cancel()
		require.Equal(t, cli.ExitOK, code, "%s: %s", tc.name, stderr.String())
		require.NotContains(t, read, envAdminURL, tc.name)
		require.NotContains(t, stdout.String()+stderr.String(), "pw@db.example", tc.name)
	}
}
