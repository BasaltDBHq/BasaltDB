package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// fakeHost records what init would do on the machine; nothing runs.
type fakeHost struct {
	euid      int
	configDir string
	claude    string // path of the claude CLI; "" when not on PATH
	sudoErr   error
	sudo      [][]string
	sudoIn    []string
	probed    []string
	ran       [][]string
	// claudeHas lists the servers claude mcp get finds; get calls are
	// recorded in got, not ran.
	claudeHas []string
	got       [][]string
	opened    []string
	openErr   error
	pagesUp   bool
	issued    []issuedLink
	issueErr  error
	sys       *fakeSys
}

const fakeBin = "/opt/basalt/bin/basalt"

func newFakeHost(t *testing.T) *fakeHost {
	// A short directory: the socket path under it must fit a Unix socket,
	// which t.TempDir on macOS does not.
	dir, err := os.MkdirTemp("/tmp", "bt")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &fakeHost{euid: 501, configDir: dir, sys: &fakeSys{written: map[string]string{}, modes: map[string]os.FileMode{}, owners: map[string]string{}}}
}

func (h *fakeHost) Euid() int                      { return h.euid }
func (h *fakeHost) Executable() (string, error)    { return fakeBin, nil }
func (h *fakeHost) UserConfigDir() (string, error) { return h.configDir, nil }
func (h *fakeHost) LookPath(string) (string, error) {
	if h.claude == "" {
		return "", errors.New("not found")
	}
	return h.claude, nil
}

func (h *fakeHost) Sudo(_ context.Context, args []string, stdin string, _, _ io.Writer) error {
	h.sudo = append(h.sudo, args)
	h.sudoIn = append(h.sudoIn, stdin)
	return h.sudoErr
}

func (h *fakeHost) Run(_ context.Context, args []string, _, _ io.Writer) error {
	if len(args) == claudeGetArgs && args[1] == "mcp" && args[2] == "get" {
		h.got = append(h.got, args)
		if slices.Contains(h.claudeHas, args[3]) {
			return nil
		}
		return errors.New("no MCP server found")
	}
	h.ran = append(h.ran, args)
	return nil
}

// claudeGetArgs is the length of claude mcp get <name>.
const claudeGetArgs = 4

func (h *fakeHost) OpenURL(_ context.Context, link string) error {
	h.opened = append(h.opened, link)
	return h.openErr
}

func (h *fakeHost) PagesUp(context.Context, string) bool { return h.pagesUp }

// IssueLink stands in for the engine's pages: it records the request and
// issues a fixed secret.
func (h *fakeHost) IssueLink(_ context.Context, endpoint, proof string) (string, error) {
	h.issued = append(h.issued, issuedLink{endpoint: endpoint, proof: proof})
	page := strings.Replace(strings.TrimSuffix(endpoint, "/links"), "/api/v1/", "/", 1)
	return page + "#s=" + fakeSecret, h.issueErr
}

// fakeSecret is the secret fakeHost issues.
const fakeSecret = "c2VjcmV0LXNlY3JldC0xMg"

type issuedLink struct{ endpoint, proof string }

func (h *fakeHost) System(io.Writer, io.Writer) service.System { return h.sys }

func (h *fakeHost) Probe(_ context.Context, socket string) error {
	h.probed = append(h.probed, socket)
	return nil
}

// fakeSys is a service.System that records steps.
type fakeSys struct {
	ran     []string
	written map[string]string
	modes   map[string]os.FileMode
	owners  map[string]string
}

func (s *fakeSys) UserExists(string) bool { return false }
func (s *fakeSys) Exists(string) bool     { return false }
func (s *fakeSys) Output(_ context.Context, args ...string) (string, error) {
	if strings.Join(args, " ") == "dscl . -list /Users UniqueID" {
		return "root 0\n", nil
	}
	return "", nil
}

func (s *fakeSys) Run(_ context.Context, args ...string) error {
	s.ran = append(s.ran, strings.Join(args, " "))
	return nil
}

func (s *fakeSys) Mkdir(path string, mode os.FileMode, owner string) error {
	s.ran = append(s.ran, fmt.Sprintf("mkdir -m %04o -o %s %s", mode, owner, path))
	return nil
}

func (s *fakeSys) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	s.owners[path] = owner
	s.written[path], s.modes[path] = string(data), mode
	return nil
}
func (s *fakeSys) Remove(string) error { return nil }

// initRun runs basalt init against d with the fake host, as if at a
// terminal when interactive.
func initRun(t *testing.T, d *guardtest.DB, h *fakeHost, goos string, interactive bool, stdin string, extra ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string {
			if k == envAdminURL {
				return d.URL
			}
			return ""
		})
	c.goos, c.host, c.interactive = goos, h, interactive
	args := append([]string{"--agent", "bot", "--write", "public.leads", "--prefix", d.Names.Prefix, "--skip-passkey"}, extra...)
	code := runInit(c, args)
	return result{code, stdout.String(), stderr.String()}
}

func me(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	return u.Username
}

func TestInitInstallsTheServiceWithOneSudo(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos, config, user, socket string
	}{
		{"linux", "/etc/basalt/engine.json", "basalt", "/run/basalt/bot.sock"},
		{"darwin", "/Library/Application Support/Basalt/engine.json", "_basalt", "/Library/Application Support/Basalt/run/bot.sock"},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			h := newFakeHost(t)
			h.claude = "/usr/local/bin/claude"
			// Answers: run the SQL, install the service (default), add to Claude Code.
			r := initRun(t, d, h, v.goos, true, "y\n\ny\n")
			require.Equal(t, exitOK, r.code, r.stderr)

			require.Len(t, h.sudo, 1, "one elevation")
			require.Equal(t, []string{fakeBin, "service", "install", "--config", v.config, "--user", v.user,
				"--agent", "bot", "--os-user", me(t), "--pages-url", links.DefaultLocal,
				"--init-arg", "--agent=bot", "--init-arg", "--write=public.leads", "--init-arg", "--prefix=" + d.Names.Prefix,
				"--init-arg", "--os-user=" + me(t), "--credential-stdin"}, h.sudo[0])
			require.Contains(t, h.sudoIn[0], d.Names.Prefix+"_agent_bot:", "the agent's credential goes on stdin")
			require.NotContains(t, strings.Join(h.sudo[0], " "), "postgres://", "never on the command line")
			require.Equal(t, []string{v.socket}, h.probed)
			require.Equal(t, [][]string{{"/usr/local/bin/claude", "mcp", "add", "basalt-bot", "--", fakeBin, "mcp", "--agent", "bot"}}, h.ran)

			require.Contains(t, r.stderr, "Install the engine as a background service? This creates the OS user "+v.user+" and needs your password once. [Y/n]")
			require.Contains(t, r.stderr, "basalt: engine running as "+v.user+"; it answered on "+v.socket)
			require.Contains(t, r.stderr, "  basalt mcp --agent bot\n")
			require.Contains(t, r.stderr, "Add it to Claude Code now (claude mcp add basalt-bot -- "+fakeBin+" mcp --agent bot)? [Y/n]")
			require.NotContains(t, r.stderr, "chown")
			require.NotContains(t, r.stderr, "basalt engine --config")
			require.NoDirExists(t, filepath.Join(h.configDir, perUserDirName), "nothing in the person's home")
		})
	}
}

func TestInitDeclinedServiceRunsInTheForeground(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.claude = "/usr/local/bin/claude"
	// Answers: run the SQL, no service, no Claude Code.
	r := initRun(t, d, h, "linux", true, "y\nn\nn\n")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.sudo)
	require.Empty(t, h.probed)
	require.Empty(t, h.ran, "claude mcp add never runs without a yes")

	dir := filepath.Join(h.configDir, perUserDirName)
	cfg, err := config.Load(filepath.Join(dir, "engine.json"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "run"), cfg.SocketDir)
	require.Equal(t, filepath.Join(dir, "state"), cfg.StateDir)
	info, err := os.Stat(filepath.Join(dir, "agents", "bot.url"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(config.FileMode), info.Mode().Perm())
	require.Contains(t, r.stderr, "next, start the engine; it runs in the foreground as you")
	require.Contains(t, r.stderr, "basalt engine --config "+shellQuote(filepath.Join(dir, "engine.json")))
	require.NotContains(t, r.stderr, "sudo")
}

func TestInitSkipsClaudeWhenItHasTheServer(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.claude = "/usr/local/bin/claude"
	h.claudeHas = []string{"basalt-bot"}
	// Answers: run the SQL, no service. Claude Code is not asked about.
	r := initRun(t, d, h, "linux", true, "y\nn\n")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, [][]string{{"/usr/local/bin/claude", "mcp", "get", "basalt-bot"}}, h.got)
	require.Empty(t, h.ran, "claude mcp add does not run for a server Claude Code has")
	require.Contains(t, r.stderr, "basalt: Claude Code already has basalt-bot\n")
	require.NotContains(t, r.stderr, "Add it to Claude Code now")
	require.NotContains(t, r.stderr, "claude mcp add failed")
}

func TestInitWithoutATerminalNeverAsks(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.claude = "/usr/local/bin/claude"
	r := initRun(t, d, h, "linux", false, "y\n")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.sudo)
	require.Empty(t, h.ran)
	require.Contains(t, r.stderr, "not at a terminal, so the engine service is not installed (pass --yes to install it)")
	require.NotContains(t, r.stderr, "[Y/n]")

	// --yes installs it without asking; Claude Code still is not touched.
	d = guardtest.New(t).WithDemo(t)
	h = newFakeHost(t)
	h.claude = "/usr/local/bin/claude"
	r = initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Len(t, h.sudo, 1)
	require.Empty(t, h.ran)

	// --no-service wins over --yes.
	d = guardtest.New(t).WithDemo(t)
	h = newFakeHost(t)
	r = initRun(t, d, h, "linux", false, "", "--yes", "--no-service")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.sudo)
	require.Contains(t, r.stderr, "basalt engine --config")
}

func TestInitAsRootInstallsInProcess(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.euid = 0
	r := initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.sudo, "already root")
	require.Equal(t, "basalt", h.sys.owners["/etc/basalt/agents/bot.url"])
	require.Contains(t, h.sys.ran, "systemctl enable --now basalt-engine.service")
	require.Contains(t, h.sys.written["/etc/basalt/agents/bot.url"], d.Names.Prefix+"_agent_bot:")
	require.Equal(t, os.FileMode(config.FileMode), h.sys.modes["/etc/basalt/agents/bot.url"])
	require.Contains(t, h.sys.written["/etc/basalt/engine.json"], `"socketDir": "/run/basalt"`)
	require.NotContains(t, r.stderr, "postgres://", "the credential is never printed")
}

func TestInitSudoFailureSaysWhatIsInstalled(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.sudoErr = errors.New("exit status 1")
	r := initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "the guard is installed but the engine service is not (run basalt init again, or with --no-service)")
	require.Empty(t, h.probed)
}

func TestInitDryRunPrintsTheServicePlan(t *testing.T) {
	t.Parallel()
	for _, v := range []struct{ goos, want string }{
		{"linux", "systemctl enable --now basalt-engine.service"},
		{"darwin", "launchctl bootstrap system /Library/LaunchDaemons/dev.basaltdb.engine.plist"},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			d := guardtest.New(t).WithDemo(t)
			h := newFakeHost(t)
			r := initRun(t, d, h, v.goos, true, "", "--dry-run")
			require.Equal(t, exitOK, r.code, r.stderr)
			require.Contains(t, r.stdout, "CREATE SCHEMA IF NOT EXISTS basalt_meta")
			require.Contains(t, r.stderr, "then init asks to install the engine service, which runs (the credential on stdin):\n  sudo "+fakeBin+" service install")
			require.Contains(t, r.stderr, v.want)
			require.Contains(t, r.stderr, "agents/bot.url")
			require.Empty(t, h.sys.ran, "a dry run runs nothing")
			require.Empty(t, h.sys.written)
			require.Empty(t, h.sudo)
			require.NotContains(t, r.stderr, "[Y/n]", "a dry run asks nothing")
		})
	}
}

func TestServiceInstallAgentReadsTheCredentialFromStdin(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "engine.json")
	spec := service.Spec{GOOS: "linux", Binary: fakeBin, ConfigPath: cfgPath, User: "basalt"}
	a := agentInstall{name: "bot", osUser: me(t)}

	_, err := agentSpecFromStdin(strings.NewReader("postgres://x\n"), spec, a, false, false)
	require.ErrorContains(t, err, "--credential-stdin")
	_, err = agentSpecFromStdin(strings.NewReader(""), spec, a, true, false)
	require.ErrorContains(t, err, "no connection string on stdin")
	_, err = agentSpecFromStdin(strings.NewReader("x\n"), spec, agentInstall{name: "bot", osUser: "no-such-user-basalt"}, true, false)
	require.ErrorContains(t, err, "no-such-user-basalt")

	got, err := agentSpecFromStdin(strings.NewReader("postgres://agent:pw@h/db\n"), spec, a, true, false)
	require.NoError(t, err)
	cred := filepath.Join(filepath.Dir(cfgPath), "agents", "bot.url")
	require.Equal(t, cred, got.Files[1].Path)
	require.Equal(t, "postgres://agent:pw@h/db\n", string(got.Files[1].Content))
	require.Equal(t, cfgPath, got.Files[0].Path)
	require.Contains(t, string(got.Files[0].Content), `"socketDir": "/run/basalt"`)
	require.Contains(t, string(got.Files[0].Content), `"credentialFile": "`+cred+`"`)
	require.NotContains(t, string(got.Files[0].Content), "pw@", "the config holds no credential")
}
