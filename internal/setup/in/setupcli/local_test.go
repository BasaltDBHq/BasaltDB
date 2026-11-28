package setupcli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
)

const (
	fakeBin = "/opt/basalt/bin/basalt"
	// olderBuild is older than any build of this binary, a test's
	// 0.0.0-dev included: the lowest version there is.
	olderBuild = "0.0.0-0"
	// newerBuild is newer than any build of this binary.
	newerBuild = "999.0.0"
)

// leakedAdmin is an admin connection string an agent was handed; no output
// may carry it.
var leakedAdmin = "postgres://postgres" + ":" + "hunter2-admin" + "@" + "db.example.com:5432/app"

type result struct {
	code           int
	stdout, stderr string
}

// fakeHost records what init would do on the machine; nothing runs. It
// answers only what basalt init on a person-operated engine asks of it.
type fakeHost struct {
	cli.Machine
	euid   int
	sudo   [][]string
	opened []string
	sys    *fakeSys
	// dialogs are the scripts the administrator dialog ran; noDialog is
	// what DialogAvailable says, dialogErr what the dialog run returns.
	dialogs   []string
	prompts   []string
	noDialog  error
	dialogErr error
	// setupCodes are what SetupState answers, one per call (the last one
	// repeats); setupErrs, while not empty, an error per call before them.
	setupCodes []string
	setupErrs  []error
	setupCalls int
	// probes are the agent and since each SetupState call named.
	probes []probe
	// build is the build the engine reports ("" is this binary's own);
	// buildErr, when set, is the engine not answering.
	build    string
	buildErr error
	// silent is an engine too old to report a build.
	silent bool
	// stuck is a restart that starts the same old build again.
	stuck bool
	// downAfterRestart is how many EngineBuild calls fail after the
	// restart (-1: always) before the engine answers.
	downAfterRestart int
	restarted        bool
	// runs are what ServiceRuns reads, one per call (the last one repeats),
	// with lastExit; none is no service manager.
	runs     []int
	lastExit int
	// userConfig is the person's config directory; "" is none.
	userConfig string
}

func newFakeHost() *fakeHost {
	return &fakeHost{euid: 501, sys: &fakeSys{}}
}

func (h *fakeHost) Euid() int { return h.euid }
func (h *fakeHost) UserConfigDir() (string, error) {
	if h.userConfig == "" {
		return "", errors.New("no config directory")
	}
	return h.userConfig, nil
}
func (h *fakeHost) ResolvedExecutable() (string, error) { return fakeBin, nil }
func (h *fakeHost) DialogAvailable(string) error        { return h.noDialog }

func (h *fakeHost) EngineBuild(context.Context, string) (string, error) {
	if h.restarted && h.downAfterRestart != 0 {
		if h.downAfterRestart > 0 {
			h.downAfterRestart--
		}
		return "", errors.New("connection refused")
	}
	if h.buildErr != nil {
		return "", h.buildErr
	}
	if h.silent {
		return "", nil
	}
	if h.build == "" {
		return buildinfo.Version, nil
	}
	return h.build, nil
}

func (h *fakeHost) ServiceRuns(context.Context, string) (int, int, error) {
	if len(h.runs) == 0 {
		return 0, 0, errors.New("no service manager here")
	}
	runs := h.runs[0]
	if len(h.runs) > 1 {
		h.runs = h.runs[1:]
	}
	return runs, h.lastExit, nil
}

// probe is what one SetupState call named.
type probe struct {
	agent string
	since time.Time
}

func (h *fakeHost) SetupState(_ context.Context, _, agent string, since time.Time) (string, error) {
	h.setupCalls++
	h.probes = append(h.probes, probe{agent, since})
	if len(h.setupErrs) > 0 {
		err := h.setupErrs[0]
		h.setupErrs = h.setupErrs[1:]
		return "", err
	}
	if len(h.setupCodes) == 0 {
		return "INVALID_ARGUMENT", nil
	}
	code := h.setupCodes[0]
	if len(h.setupCodes) > 1 {
		h.setupCodes = h.setupCodes[1:]
	}
	return code, nil
}

func (h *fakeHost) AdminDialog(_ context.Context, _, prompt, script string, _ io.Writer) error {
	h.prompts = append(h.prompts, prompt)
	h.dialogs = append(h.dialogs, script)
	h.restarted = true
	if h.dialogErr == nil && !h.stuck {
		h.build, h.silent = "", false // the restart runs this binary
	}
	return h.dialogErr
}

func (h *fakeHost) OpenURL(_ context.Context, link string) error {
	h.opened = append(h.opened, link)
	return nil
}

func (h *fakeHost) System(io.Writer, io.Writer) cli.System { return h.sys }

// fakeSys is a cli.System that knows which files exist.
type fakeSys struct {
	cli.System
	// existing are the files Exists finds (an installed unit).
	existing map[string]bool
}

func (s *fakeSys) Exists(path string) bool { return s.existing[path] }

// CheckBinary passes only the service's own copy: the running basalt is a
// Homebrew-like one the person's account owns, which init never asks root
// to run.
func (s *fakeSys) CheckBinary(path string) error {
	if path != osservice.ServiceBinary("linux") {
		return errors.New(path + " is owned by uid 501, not root")
	}
	return nil
}

// localHost is the engine service's fixed scripts, as the real host has them.
type localHost struct{}

// fakeSum stands in for the running basalt's SHA-256: the fake binary is
// not on disk.
var fakeSum = strings.Repeat("cd", 32)

func (localHost) OSInstallScript(goos, binary string) (string, error) {
	return osservice.InstallScript(goos, osservice.Source{Path: binary, SHA256: fakeSum, Size: 1})
}

func (localHost) OSRestartScript(goos, binary string) (string, error) {
	return osservice.RestartScript(goos, osservice.Source{Path: binary, SHA256: fakeSum, Size: 1})
}

func (localHost) OSServiceBinary(goos string) string { return osservice.ServiceBinary(goos) }

func (localHost) OSRemoveScript(goos string) (string, error) { return osservice.RemoveScript(goos) }

func (localHost) OSResetScript(goos string) (string, error) { return osservice.ResetScript(goos) }
func (localHost) OSDefaultUser(goos string) string          { return osservice.DefaultUser(goos) }
func (localHost) OSUnitPath(goos string) string             { return osservice.UnitPath(goos) }

// newIO is the CLI's I/O on the fake machine, without the shell.
func newIO(ctx context.Context, in io.Reader, out, errw io.Writer, getenv func(string) string) *cli.IO {
	return &cli.IO{
		Ctx: ctx, Stdin: bufio.NewReader(in), Stdout: out, Stderr: errw,
		Getenv: getenv, Now: time.Now, Goos: "linux",
	}
}

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
	c := newIO(ctx, strings.NewReader("y\ny\ny\n"), &stdout, &stderr, getenv)
	c.Goos, c.Host, c.Interactive = "linux", h, true
	code := setupcli.RunLocal(c, localHost{}, args)
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
	h := newFakeHost()
	// The engine is still starting, then waits for its config.
	h.setupErrs = []error{errors.New("connection refused"), errors.New("connection refused")}
	r, read := localInit(t, h, "--demo")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)

	script, err := osservice.InstallScript("linux", osservice.Source{Path: fakeBin, SHA256: fakeSum, Size: 1})
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog")
	require.Contains(t, r.stderr, "copy "+fakeBin+" to "+osservice.ServiceBinary("linux")+", root's,")
	require.Contains(t, r.stderr, osservice.ServiceBinary("linux")+" engine --config ", "the service runs its own copy")
	require.NotContains(t, r.stderr+r.stdout, "sudo", "nothing tells the person or the agent to run sudo")
	require.Equal(t, []string{servicespec.InstallPrompt}, h.prompts, "the dialog names the install")
	require.Empty(t, h.sudo, "no sudo")
	require.Equal(t, 3, h.setupCalls, "init waited for the setup page")

	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	require.Len(t, lines, 2, "stdout is the link and the MCP line, nothing else")
	require.True(t, strings.HasPrefix(lines[0], "http://localhost:8787/setup/#1."), lines[0])
	require.Equal(t, "basalt mcp --agent demo_bot", lines[1])
	require.Equal(t, localsetup.Job{Job: setup.JobInstall, Agent: "demo_bot", OSUser: me752(t), Demo: true}, linkJob(t, lines[0]))
	require.Equal(t, []string{lines[0]}, h.opened, "init opens its own link")

	require.NotContains(t, read, envAdminURL, "init never reads the admin connection string")
	require.NotContains(t, r.stderr, "[Y/n]", "init asks nothing in the terminal")
	require.NotContains(t, r.stderr, "Admin connection string")
	require.NotContains(t, r.stdout+r.stderr, "pw@db.example")
}

// A config 0.0.1 left in the person's own folder (its shape: the agent's
// own credentialFile) is moved aside, whole and never deleted, once the
// dialog installed the service; init says so in one line and goes on as a
// first install, with the MCP line to register again. A config of today's
// shape there (basalt init --remote's) stays.
func TestInitMovesAConfigFromBeforeTheLastBreakingReleaseAside(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.userConfig = t.TempDir()
	dir := filepath.Join(h.userConfig, "basalt")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	old := `{"socketDir": "/s", "agents": [{"name": "demo_bot", "osUser": "alice", "credentialFile": "` + dir + `/agents/demo_bot.url"}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "engine.json"), []byte(old), 0o600))
	r, _ := localInit(t, h, "--demo")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.dialogs, 1, "one password")
	require.NoDirExists(t, dir)
	require.FileExists(t, filepath.Join(dir+".old", "engine.json"), "moved, never deleted")
	require.Contains(t, r.stderr, "basalt: "+filepath.Join(dir, "engine.json")+" was written by a BasaltDB release before the last breaking one: its folder is moved to "+dir+".old")
	require.Contains(t, r.stdout, "\nbasalt mcp --agent demo_bot\n", "the line the agent registers again")

	today := newFakeHost()
	today.userConfig = t.TempDir()
	kept := filepath.Join(today.userConfig, "basalt")
	require.NoError(t, os.MkdirAll(kept, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(kept, "engine.json"), []byte(`{"breaking": 1, "socketDir": "/s", "agents": []}`), 0o600))
	r, _ = localInit(t, today, "--demo")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.DirExists(t, kept)
	require.NotContains(t, r.stderr, "breaking")
}

// Without --demo the link opens the page's install of the person's own
// tables: the same dialog, link and MCP line, with demo false.
func TestInitWithoutDemoOpensTheInstallOfARealDatabase(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	r, read := localInit(t, h, "--agent", "sales_bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.dialogs, 1, "the engine service is installed through the dialog, as for --demo")
	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	require.Len(t, lines, 2, r.stdout)
	require.Equal(t, localsetup.Job{Job: setup.JobInstall, Agent: "sales_bot", OSUser: me752(t), Demo: false}, linkJob(t, lines[0]))
	require.Equal(t, "basalt mcp --agent sales_bot", lines[1])
	require.Equal(t, []string{lines[0]}, h.opened)
	require.NotContains(t, read, envAdminURL)
}

func TestInitWithTheServiceInstalledAsksNoPassword(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	r, _ := localInit(t, h, "--demo", "--agent", "sales_bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Empty(t, h.dialogs)
	require.Equal(t, "sales_bot", linkJob(t, strings.SplitN(r.stdout, "\n", 2)[0]).Agent)
}

// An engine service that runs another build than init is restarted through
// the dialog, with the fixed restart script and its prompt; an engine too
// old to report a build counts as another one.
func TestInitRestartsAnEngineThatRunsAnotherBuild(t *testing.T) {
	t.Parallel()
	for _, build := range []string{olderBuild, ""} {
		h := newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.build, h.silent = build, build == ""
		r, _ := localInit(t, h, "--demo")
		require.Equal(t, cli.ExitOK, r.code, r.stderr)
		want, err := osservice.RestartScript("linux", osservice.Source{Path: fakeBin, SHA256: fakeSum, Size: 1})
		require.NoError(t, err)
		require.Contains(t, want, "copy_binary", "the upgraded basalt is copied to the service in the same dialog")
		require.Equal(t, []string{want}, h.dialogs)
		require.Equal(t, []string{servicespec.RestartPrompt}, h.prompts)
		require.Contains(t, r.stderr, "different build")
		require.Contains(t, h.opened[0], "#1.", "init goes on to the link")
	}
}

// An engine on a newer build than this basalt is never moved back: init
// opens no dialog and says to update this basalt first, with no sudo.
func TestInitNeverMovesTheServiceToAnOlderBuild(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.build = newerBuild
	r, _ := localInit(t, h, "--demo")
	require.Equal(t, cli.ExitError, r.code, r.stderr)
	require.Empty(t, h.dialogs, "no password for a downgrade")
	require.Contains(t, r.stderr, "runs basalt "+newerBuild+", newer than this basalt")
	require.Contains(t, r.stderr, "Update this basalt to "+newerBuild+" or later first")
	require.NotContains(t, r.stderr, "sudo")
	require.Empty(t, h.opened)
}

// The same build, an engine that does not answer, and a first install
// restart nothing.
func TestInitRestartsNothingWhenTheBuildsMatch(t *testing.T) {
	t.Parallel()
	same := newFakeHost()
	same.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	down := newFakeHost()
	down.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	down.buildErr = errors.New("connection refused")
	fresh := newFakeHost()
	fresh.build = olderBuild
	for _, h := range []*fakeHost{same, down, fresh} {
		r, _ := localInit(t, h, "--demo")
		require.Equal(t, cli.ExitOK, r.code, r.stderr)
		for _, p := range h.prompts {
			require.NotEqual(t, servicespec.RestartPrompt, p)
		}
	}
}

// With no dialog the restart stops init and says to run basalt init again
// (never a root command: the agent has no terminal for a password); a
// closed dialog stops it too, and the link is not opened.
func TestInitRestartStops(t *testing.T) {
	t.Parallel()
	noDialog := newFakeHost()
	noDialog.noDialog = servicespec.ErrNoDialog
	closed := newFakeHost()
	closed.dialogErr = servicespec.ErrDialogCancelled
	for name, h := range map[string]*fakeHost{"no dialog": noDialog, "closed": closed} {
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.build = olderBuild
		r, _ := localInit(t, h, "--demo")
		require.Equal(t, cli.ExitError, r.code, name)
		require.Contains(t, r.stderr, "different build", name)
		require.Empty(t, h.opened, name)
		require.Contains(t, r.stderr, "basalt init again", name)
		require.NotContains(t, r.stderr, "sudo", name)
		require.NotContains(t, r.stderr, "systemctl restart", "no root command for a person or an agent to type")
	}
}

// A restart that leaves the service on another build stops init and names
// the unit that starts the other binary; another dialog failure says to run
// basalt init again.
// The engine is down while it restarts: init waits for /healthz before it
// reads the build again, and goes on once it answers.
func TestInitRestartWaitsForTheEngineToAnswer(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.build = olderBuild
	h.downAfterRestart = 3
	r, _ := localInit(t, h, "--demo")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Zero(t, h.downAfterRestart, "it polled until the engine answered")
	require.Contains(t, r.stderr, "restarted onto this build")
}

// An engine that never answers after the restart is not a success: init
// stops, says so and says to run basalt init again.
func TestInitRestartStopsWhenTheEngineNeverAnswers(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.build = olderBuild
	h.downAfterRestart = -1
	r, _ := localInitWithin(t, 2*time.Second, h, "--demo")
	require.Equal(t, cli.ExitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "did not answer")
	require.Contains(t, r.stderr, "run basalt init again")
	require.NotContains(t, r.stderr, "systemctl restart")
	require.NotContains(t, r.stderr, "restarted onto this build")
	require.Empty(t, h.opened)
}

func TestInitRestartThatChangesNothingOrFails(t *testing.T) {
	t.Parallel()
	stuck := newFakeHost()
	stuck.stuck = true
	failed := newFakeHost()
	failed.dialogErr = errors.New("osascript exploded")
	for name, h := range map[string]*fakeHost{"stuck": stuck, "failed": failed} {
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.build = olderBuild
		r, _ := localInit(t, h, "--demo")
		require.Equal(t, cli.ExitError, r.code, name)
		require.Contains(t, r.stderr, "basalt init again", name)
		require.NotContains(t, r.stderr, "systemctl restart", name)
		require.NotContains(t, r.stderr, "sudo", name)
		require.Empty(t, h.opened, name)
		if name == "stuck" {
			require.Contains(t, r.stderr, osservice.UnitPath("linux"))
		}
	}
}

func TestInitOnASetUpEngineOpensTheChangeLink(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"--demo"}, {"--agent", "sales_bot"}} {
		h := newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{setup.CodeJobUnavailable}
		r, read := localInitWithin(t, 2*time.Second, h, args...)
		require.Equal(t, cli.ExitOK, r.code, "%v: %s", args, r.stderr)
		require.Contains(t, r.stderr, "this init stops waiting. The page needs nothing more from the agent.", "no Remove within the wait: init returns, and removes nothing")
		require.Empty(t, h.dialogs, "no password: the service is there")
		lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
		require.Len(t, lines, 1, "stdout is the link only: the agent is registered already")
		agent := "demo_bot"
		if len(args) == 2 {
			agent = args[1]
		}
		require.Equal(t, localsetup.Job{Job: setup.JobChange, Agent: agent, OSUser: me752(t)}, linkJob(t, lines[0]), "%v", args)
		require.Equal(t, []string{lines[0]}, h.opened, "init opens its own link")
		require.Contains(t, r.stderr, "update the guard or remove BasaltDB")
		const demoLine = "basalt: --demo starts a fresh demo, and BasaltDB is already set up on this computer. To start over with the demo: on the page that opened, press Remove, then run basalt init --demo again.\n"
		if len(args) == 1 && args[0] == "--demo" {
			require.Contains(t, r.stderr, demoLine)
		} else {
			require.NotContains(t, r.stderr, "--demo starts a fresh demo", "%v", args)
		}
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
		{"an admin-flow flag", []string{"--demo", "--write", "public.leads"}, nil, cli.ExitUsage, "takes only --agent, --demo and --remove"},
		{"the old --yes", []string{"--demo", "--yes"}, nil, cli.ExitUsage, "takes only --agent, --demo and --remove"},
		{"a bad agent name", []string{"--demo", "--agent", "Bad-Name"}, nil, cli.ExitUsage, "is not a name an agent can have"},
		{"root", []string{"--demo"}, func(h *fakeHost) { h.euid = 0 }, cli.ExitUsage, "not root"},
		{"no dialog", []string{"--demo"}, func(h *fakeHost) { h.noDialog = fmt.Errorf("%w (/usr/bin/pkexec is missing)", servicespec.ErrNoDialog) }, cli.ExitError, "cannot be shown here"},
	} {
		h := newFakeHost()
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
	h := newFakeHost()
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
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{3, 3, 4}, 1
	start := time.Now()
	r, _ := localInitWithin(t, 5*time.Second, h, "--demo")
	require.Equal(t, cli.ExitError, r.code)
	require.Contains(t, r.stderr, "the engine service keeps stopping: it started 4 times and last exited with code 1")
	require.Contains(t, r.stderr, "journalctl -u "+servicespec.SystemdUnitName)
	require.Less(t, time.Since(start), 2*time.Second, "no wait for the setup page's whole bound")
	require.Empty(t, r.stdout)

	h = newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{1}, -1
	r, _ = localInitWithin(t, time.Second, h, "--demo")
	require.Contains(t, r.stderr, "did not answer on", "one run that never exited is still starting")

	h = newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupErrs, h.runs, h.lastExit = refused(), []int{5}, 1
	r, _ = localInitWithin(t, time.Second, h, "--demo")
	require.Contains(t, r.stderr, "did not answer on", "crashes from before this wait are not this wait's")
}

// After the page's Remove, an engine its removal job did not remove yet
// (it still runs, serving no agent) sets up again on basalt init, --demo
// or not: the install link, no removal, no dialog, no wait.
func TestInitOnARemovedEngineSetsUpAgain(t *testing.T) {
	t.Parallel()
	for _, demo := range []bool{false, true} {
		h := newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{setup.CodeEngineRemoved}
		args := []string{}
		if demo {
			args = append(args, "--demo")
		}
		r, read := localInit(t, h, args...)
		require.Equal(t, cli.ExitOK, r.code, r.stderr)
		require.Empty(t, h.dialogs, "never a dialog")
		require.Equal(t, 1, h.setupCalls, "no wait")
		require.Len(t, h.opened, 1)
		require.Equal(t, localsetup.Job{Job: setup.JobInstall, Agent: "demo_bot", OSUser: me752(t), Demo: demo}, linkJob(t, h.opened[0]))
		require.Contains(t, r.stderr, "basalt: BasaltDB was removed from your database earlier. Setting up again on this computer's engine.\n")
		require.Contains(t, r.stdout, "basalt mcp --agent demo_bot")
		require.NotContains(t, read, envAdminURL)
	}
}

// A Remove on the page within the wait ends it at once: the engine's
// removal job removes it from this computer, so init asks for no password
// and runs nothing.
func TestInitEndsWhenThePageRemovesBasaltDB(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true, "/etc/basalt": true}
	h.setupCodes = []string{setup.CodeJobUnavailable, setup.CodeJobUnavailable, setup.CodeEngineRemoved}
	r, _ := localInit(t, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.opened, 1, "init opened the Update/Remove link")
	require.Empty(t, h.dialogs, "no password")
	require.Empty(t, h.sudo)
	require.Equal(t, 3, h.setupCalls, "the wait ended on ENGINE_REMOVED")
	require.Contains(t, r.stderr, "the engine is removing itself from this computer")
}

// "No, this isn't mine" on the page within the wait (Not your database):
// the init that opened the Update check resets the engine through the
// administrator dialog with the fixed reset script, then opens the install
// link once the engine waits for a first install.
func TestInitResetsThroughTheDialogThenOpensTheInstallLink(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{
		setup.CodeJobUnavailable, setup.CodeJobUnavailable, setup.CodeResetAsked, setup.CodeInvalidArgument,
	}
	r, read := localInit(t, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	script, err := osservice.ResetScript("linux")
	require.NoError(t, err)
	require.Equal(t, []string{script}, h.dialogs, "one password, in the administrator dialog, for the fixed reset script")
	require.Equal(t, []string{servicespec.ResetPrompt}, h.prompts, "the dialog names the reset")
	require.Empty(t, h.sudo)
	require.Len(t, h.opened, 2, "the Update check's link, then the install link")
	require.Equal(t, localsetup.Job{Job: setup.JobChange, Agent: "demo_bot", OSUser: me752(t)}, linkJob(t, h.opened[0]))
	require.Equal(t, localsetup.Job{Job: setup.JobInstall, Agent: "demo_bot", OSUser: me752(t)}, linkJob(t, h.opened[1]))
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
		h := newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{setup.CodeJobUnavailable, setup.CodeResetAsked}
		v.edit(h)
		r, _ := localInit(t, h)
		require.Equal(t, cli.ExitError, r.code, v.name)
		require.Contains(t, r.stderr, v.want, v.name)
		require.Len(t, h.opened, 1, "%s: no install link", v.name)
		if v.name == "no dialog" {
			require.Empty(t, h.dialogs)
		}
	}

	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
	h.setupCodes = []string{setup.CodeResetAsked, setup.CodeJobUnavailable}
	r, _ := localInitWithin(t, 3*time.Second, h)
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Empty(t, h.dialogs, "a No left from an earlier page resets nothing")
	require.Len(t, h.opened, 1)
	require.Equal(t, setup.JobChange, linkJob(t, h.opened[0]).Job)
}

// The page's Update for the agent within the wait: the init that opened
// the link says the agent can go on and exits 0 at once, without waiting
// out the 90 seconds and without a dialog. Its probes name the agent and
// when this init opened the link, so the engine never answers it for an
// Update that finished before.
func TestInitEndsAsSoonAsThePageUpdatedTheGuard(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{nil, {"--agent", "sales_bot"}} {
		agent := "demo_bot"
		if len(args) == 2 {
			agent = args[1]
		}
		h := newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{setup.CodeJobUnavailable, setup.CodeJobUnavailable, setup.CodeGuardUpdated, setup.CodeEngineRemoved}
		start := time.Now()
		r, _ := localInit(t, h, args...)
		require.Less(t, time.Since(start), 10*time.Second, "%v: init ends within a poll step, not after the wait", args)
		require.Equal(t, cli.ExitOK, r.code, r.stderr)
		require.Contains(t, r.stderr, "basalt: the guard is updated on the setup page. The agent "+agent+" can go on; it needs no restart.\n")
		require.NotContains(t, r.stderr, "after a Remove on that page")
		require.Empty(t, h.dialogs, "an Update needs no password")
		require.Len(t, h.opened, 1)
		require.Equal(t, 3, h.setupCalls, "%v: the ENGINE_REMOVED after it is never asked", args)
		require.Equal(t, probe{}, h.probes[0], "the probe before the link names nothing")
		for _, p := range h.probes[1:] {
			require.Equal(t, agent, p.agent)
			require.False(t, p.since.Before(start), "since is this init's, after it started")
			require.False(t, p.since.After(time.Now()))
			require.Equal(t, h.probes[1].since, p.since, "one since for the whole wait")
		}
	}
}

func TestInitWaitsAsLongAsAnApprovalWait(t *testing.T) {
	t.Parallel()
	require.Equal(t, 90*time.Second, setup.RemovalWait)
}

// envAdminURL is the name an admin connection string was once set under.
const envAdminURL = "BASALT_ADMIN_DATABASE_URL"

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
		c := newIO(ctx, strings.NewReader(leakedAdmin+"\n"), &stdout, &stderr, getenv)
		c.Goos, c.Host, c.Interactive = "linux", newFakeHost(), tc.interactive
		code := setupcli.RunLocal(c, localHost{}, []string{"--demo"})
		cancel()
		require.Equal(t, cli.ExitOK, code, "%s: %s", tc.name, stderr.String())
		require.NotContains(t, read, envAdminURL, tc.name)
		require.NotContains(t, stdout.String()+stderr.String(), "pw@db.example", tc.name)
	}
}

// basalt init --remove: the person asked to remove BasaltDB. On an engine
// set up it opens the removal's own link (job REMOVE, no pick first) and
// waits as the change link does; a Remove on the page ends the wait.
func TestInitRemoveOpensTheRemovalLink(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true, "/etc/basalt": true}
	h.setupCodes = []string{setup.CodeJobUnavailable, setup.CodeJobUnavailable, setup.CodeEngineRemoved}
	r, read := localInit(t, h, "--remove", "--agent", "sales_bot")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Len(t, h.opened, 1)
	require.Equal(t, localsetup.Job{Job: setup.JobRemove, Agent: "sales_bot", OSUser: me752(t)}, linkJob(t, h.opened[0]))
	require.Equal(t, h.opened[0]+"\n", r.stdout, "no basalt mcp line: the agent is registered already")
	require.Contains(t, r.stderr, "paste your database's admin connection string and press Remove")
	require.Contains(t, r.stderr, "the engine is removing itself from this computer")
	require.Empty(t, h.dialogs)
	require.NotContains(t, read, envAdminURL)
}

// Where nothing is set up, --remove installs nothing and says so; it
// never goes with --demo.
func TestInitRemoveWithNothingToRemove(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	r, _ := localInit(t, h, "--remove")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "BasaltDB is not set up on this computer, so there is nothing to remove.")
	require.Empty(t, h.dialogs, "a removal never installs the engine service")
	require.Empty(t, h.opened)

	// An engine that serves no agent (a removal its job did not finish, or
	// one never set up) is removed through the administrator dialog.
	script, err := osservice.RemoveScript("linux")
	require.NoError(t, err)
	for _, code := range []string{setup.CodeEngineRemoved, "INVALID_ARGUMENT"} {
		h = newFakeHost()
		h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true}
		h.setupCodes = []string{code}
		r, _ = localInit(t, h, "--remove")
		require.Equal(t, cli.ExitOK, r.code, r.stderr)
		require.Equal(t, []string{script}, h.dialogs, "%s: one password, the fixed removal script", code)
		require.Equal(t, []string{servicespec.RemovePrompt}, h.prompts)
		require.Contains(t, r.stderr, "the engine service is removed from this computer")
		require.Empty(t, h.opened)
	}

	r, _ = localInit(t, newFakeHost(), "--remove", "--demo")
	require.Equal(t, cli.ExitUsage, r.code)
	require.Contains(t, r.stderr, "--remove and --demo do not go together")
}

// A Remove that leaves the engine other agents ends the wait at once
// (AGENT_REMOVED): no ENGINE_REMOVED comes, and init does not wait the
// full 90 seconds.
func TestInitEndsWhenThePageRemovesOneAgentOfMany(t *testing.T) {
	t.Parallel()
	h := newFakeHost()
	h.sys.existing = map[string]bool{osservice.UnitPath("linux"): true, "/etc/basalt": true}
	h.setupCodes = []string{setup.CodeJobUnavailable, setup.CodeJobUnavailable, setup.CodeAgentRemoved}
	r, _ := localInit(t, h, "--remove")
	require.Equal(t, cli.ExitOK, r.code, r.stderr)
	require.Equal(t, 3, h.setupCalls)
	require.Contains(t, r.stderr, "The engine stays on this computer for its other agents.")
	require.Empty(t, h.dialogs)
}
