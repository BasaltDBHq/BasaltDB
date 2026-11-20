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
	// issueURL, when set, is the link IssueLink answers with instead of
	// the item's page.
	issueURL string
	sys      *fakeSys
	// probeErr is what Probe returns; engineLog what EngineLog reads.
	probeErr  error
	engineLog string
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
	if h.issueURL != "" {
		return h.issueURL, h.issueErr
	}
	page := strings.Replace(strings.TrimSuffix(endpoint, "/links"), "/api/v1/", "/", 1)
	return page + "#s=" + fakeSecret, h.issueErr
}

// fakeSecret is the secret fakeHost issues.
const fakeSecret = "c2VjcmV0LXNlY3JldC0xMg"

type issuedLink struct{ endpoint, proof string }

func (h *fakeHost) System(io.Writer, io.Writer) service.System { return h.sys }

func (h *fakeHost) Probe(_ context.Context, socket string) error {
	h.probed = append(h.probed, socket)
	return h.probeErr
}

func (h *fakeHost) EngineLog(context.Context, string) (string, error) { return h.engineLog, nil }

// fakeSys is a service.System that records steps.
type fakeSys struct {
	ran     []string
	written map[string]string
	modes   map[string]os.FileMode
	owners  map[string]string
	// binaryErr is what CheckBinary returns; checked records its calls.
	binaryErr error
	checked   []string
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

func (s *fakeSys) Mkdir(path string, mode os.FileMode, owner, group string) error {
	s.ran = append(s.ran, fakeMkdir(path, mode, owner, group))
	return nil
}

func (s *fakeSys) RemoveTree(path string) error {
	s.ran = append(s.ran, "rm -rf "+path)
	return nil
}

func (s *fakeSys) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	s.owners[path] = owner
	s.written[path], s.modes[path] = string(data), mode
	return nil
}

func (s *fakeSys) CreateFile(path string, mode os.FileMode, owner string) error {
	s.ran = append(s.ran, fmt.Sprintf("create -m %04o -o %s %s", mode.Perm(), owner, path))
	return nil
}

func (s *fakeSys) MoveAside(path, owner string) (string, error) {
	s.ran = append(s.ran, "move-aside "+path+" "+owner)
	return "", nil
}
func (s *fakeSys) Remove(string) error                  { return nil }
func (s *fakeSys) InGroup(string, string) (bool, error) { return false, nil }
func (s *fakeSys) CheckBinary(path string) error {
	s.checked = append(s.checked, path)
	return s.binaryErr
}

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
			require.Equal(t, []string{
				fakeBin, "service", "install", "--config", v.config, "--user", v.user,
				"--agent", "bot", "--os-user", me(t), "--pages-url", links.DefaultLocal, "--vault-default=off",
				"--init-arg", "--agent=bot", "--init-arg", "--write=public.leads", "--init-arg", "--prefix=" + d.Names.Prefix,
				"--init-arg", "--os-user=" + me(t), "--person-uid", "501", "--credential-stdin",
			}, h.sudo[0])
			require.Contains(t, h.sudoIn[0], d.Names.Prefix+"_agent_bot:", "the agent's credential goes on stdin")
			require.NotContains(t, strings.Join(h.sudo[0], " "), "postgres://", "never on the command line")
			require.Equal(t, []string{v.socket}, h.probed)
			require.Equal(t, [][]string{{"/usr/local/bin/claude", "mcp", "add", "--scope", "local", "basalt-bot", "--", fakeBin, "mcp", "--agent", "bot"}}, h.ran)

			require.Contains(t, r.stderr, "Install the engine as a background service? This creates the OS user "+v.user+" and needs your password once. [Y/n]")
			require.Contains(t, r.stderr, "basalt: engine running as "+v.user+"; it answered on "+v.socket)
			require.Contains(t, r.stderr, "  basalt mcp --agent bot\n")
			require.Contains(t, r.stderr, "Add it to Claude Code now (claude mcp add --scope local basalt-bot -- "+fakeBin+" mcp --agent bot)? [Y/n]")
			require.Contains(t, r.stderr, "basalt: the server basalt-bot is registered for this project directory only (--scope local); sessions in other projects do not see it\n")
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
	require.Equal(t, config.VaultOff, cfg.Vault, "person mode: the Vault is off by default")
	require.Contains(t, r.stderr, "basalt: vault: off (default in person mode, where the engine serves its own pages)\n")
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
	// Piped answers without --yes or --no-service: init does not pick the
	// engine's mode for the person, and stops before anything is written.
	r := initRun(t, d, h, "linux", false, "y\n")
	require.Equal(t, exitUsage, r.code, r.stderr)
	require.Contains(t, r.stderr, "--yes")
	require.Contains(t, r.stderr, "--no-service")
	require.Empty(t, r.stdout, "no SQL shown")
	require.Empty(t, h.sudo)
	require.Empty(t, h.ran)
	require.NoDirExists(t, filepath.Join(h.configDir, perUserDirName), "no credential in the person's home")
	var installed bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'basalt_meta')`).Scan(&installed))
	require.False(t, installed, "the database is left as it was")
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
	r := initRun(t, d, h, "linux", false, "", "--yes", "--person-uid", "4242")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.sudo, "already root")
	require.Contains(t, h.sys.written["/etc/basalt/engine.json"], `"mode": "SERVICE"`)
	require.Contains(t, h.sys.written["/etc/basalt/engine.json"], "4242")
	require.Equal(t, "basalt", h.sys.owners["/etc/basalt/agents/bot.url"])
	require.Contains(t, h.sys.ran, "systemctl enable --now basalt-engine.service")
	require.Contains(t, h.sys.written["/etc/basalt/agents/bot.url"], d.Names.Prefix+"_agent_bot:")
	require.Equal(t, os.FileMode(config.FileMode), h.sys.modes["/etc/basalt/agents/bot.url"])
	require.Contains(t, h.sys.written["/etc/basalt/engine.json"], `"socketDir": "/run/basalt"`)
	require.Contains(t, h.sys.written["/etc/basalt/engine.json"], `"vault": "OFF"`, "a new config: the person-mode default")
	require.Contains(t, r.stderr, "basalt: vault: off (default in person mode, where the engine serves its own pages)\n")
	require.NotContains(t, r.stderr, "postgres://", "the credential is never printed")
}

func TestInitAsRootWithoutAPersonInstallsNoService(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	h.euid = 0
	// A root login without SUDO_UID names the person, or no service.
	r := initRun(t, d, h, "linux", false, "", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "give --person-uid N")
	require.Empty(t, h.sys.ran, "nothing installed without a person")
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

func TestInitYesPrintsAShortSQLSummary(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	h := newFakeHost(t)
	r := initRun(t, d, h, "linux", false, "", "--yes", "--no-service")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stdout, "CREATE SCHEMA")
	require.LessOrEqual(t, strings.Count(r.stdout, "\n"), 24, "at most a screenful")
	require.Contains(t, r.stdout, "basalt: this setup SQL will:")
	require.Contains(t, r.stdout, "- install or upgrade the guard (basalt_meta)")
	require.Contains(t, r.stdout, "- create the agent role")
	require.Contains(t, r.stdout, "- let the agent write public.leads")
	require.Contains(t, r.stdout, "Pass --show-sql to print the SQL (passwords redacted).")

	d = guardtest.New(t).WithDemo(t)
	h = newFakeHost(t)
	r = initRun(t, d, h, "linux", false, "", "--yes", "--no-service", "--show-sql")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "CREATE SCHEMA IF NOT EXISTS basalt_meta")
	require.NotContains(t, r.stdout, "Pass --show-sql")
}

func TestServiceInstallAgentReadsTheCredentialFromStdin(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "engine.json")
	spec := service.Spec{GOOS: "linux", Binary: fakeBin, ConfigPath: cfgPath, User: me(t)}
	a := agentInstall{name: "bot", osUser: agentOSUser(t), personUIDs: []uint32{4242}}

	_, err := agentSpecFromStdin(strings.NewReader("postgres://x\n"), spec, a, false, false)
	require.ErrorContains(t, err, "--credential-stdin")
	_, err = agentSpecFromStdin(strings.NewReader(""), spec, a, true, false)
	require.ErrorContains(t, err, "no connection string on stdin")
	_, err = agentSpecFromStdin(strings.NewReader("x\n"), spec, agentInstall{name: "bot", osUser: "no-such-user-basalt"}, true, false)
	require.ErrorContains(t, err, "no-such-user-basalt")

	noPerson := agentInstall{name: "bot", osUser: agentOSUser(t)}
	_, err = agentSpecFromStdin(strings.NewReader("x\n"), spec, noPerson, true, false)
	require.ErrorIs(t, err, errNoPerson, "no person uid: no service")
	noPerson.personUIDs = []uint32{0}
	_, err = agentSpecFromStdin(strings.NewReader("x\n"), spec, noPerson, true, false)
	require.ErrorContains(t, err, "is root", "root is never a person")

	got, err := agentSpecFromStdin(strings.NewReader("postgres://agent:pw@h/db\n"), spec, a, true, false)
	require.NoError(t, err)
	require.Contains(t, string(got.Files[0].Content), `"mode": "SERVICE"`)
	require.Contains(t, string(got.Files[0].Content), "\"personUids\": [\n    4242\n  ]")
	cred := filepath.Join(filepath.Dir(cfgPath), "agents", "bot.url")
	require.Equal(t, cred, got.Files[1].Path)
	require.Equal(t, "postgres://agent:pw@h/db\n", string(got.Files[1].Content))
	require.Equal(t, cfgPath, got.Files[0].Path)
	require.Contains(t, string(got.Files[0].Content), `"socketDir": "/run/basalt"`)
	require.Contains(t, string(got.Files[0].Content), `"credentialFile": "`+cred+`"`)
	require.NotContains(t, string(got.Files[0].Content), "pw@", "the config holds no credential")
	require.NotContains(t, string(got.Files[0].Content), `"vault"`, "no --vault: the config's stays")

	a.vault = config.VaultOn
	got, err = agentSpecFromStdin(strings.NewReader("postgres://agent:pw@h/db\n"), spec, a, true, false)
	require.NoError(t, err)
	require.Contains(t, string(got.Files[0].Content), `"vault": "ON"`, "--vault writes the config's vault")
}

// A binary anyone but root could change is refused before init asks for the
// admin connection, connects, or runs sudo: the database is left as it was
// and the agent's replacement never runs as root.
func TestInitRefusesUnprotectedBinaryBeforeAnything(t *testing.T) {
	t.Parallel()
	for _, extra := range [][]string{{"--yes"}, {"--dry-run"}} {
		h := newFakeHost(t)
		h.sys.binaryErr = errors.New("/opt/basalt/bin is owned by uid 501, not root")
		var stdout, stderr bytes.Buffer
		getenv := func(k string) string {
			if k == envAdminURL {
				return "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"
			}
			return ""
		}
		c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, getenv)
		c.goos, c.host = "linux", h
		code := runInit(c, append([]string{"--agent", "bot", "--write", "public.leads", "--skip-passkey"}, extra...))

		require.Equal(t, exitError, code, extra)
		require.Contains(t, stderr.String(), "owned by uid 501, not root", extra)
		require.Contains(t, stderr.String(), "--no-service", extra)
		require.NotContains(t, stderr.String(), "connect:", "init never connects")
		require.Empty(t, stdout.String(), "no SQL is planned")
		require.Equal(t, []string{fakeBin}, h.sys.checked)
		require.Empty(t, h.sudo)
	}
}

// With --no-service init never hands the binary to sudo, so it is not checked.
func TestInitNoServiceDoesNotCheckTheBinary(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	h.sys.binaryErr = errors.New("unprotected")
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: io.Discard, err: io.Discard},
		func(k string) string {
			if k == envAdminURL {
				return "postgres://nobody@127.0.0.1:1/none?connect_timeout=1"
			}
			return ""
		})
	c.goos, c.host = "linux", h
	runInit(c, []string{"--agent", "bot", "--write", "public.leads", "--skip-passkey", "--yes", "--no-service"})
	require.Empty(t, h.sys.checked)
}

// fakeMkdir is how the fakes record a mkdir step: the path as it is.
func fakeMkdir(path string, mode os.FileMode, owner, group string) string {
	bits := uint32(mode.Perm())
	if mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if owner == "" {
		owner = "root"
	}
	if group != "" {
		owner += " -g " + group
	}
	return fmt.Sprintf("mkdir -m %04o -o %s %s", bits, owner, path)
}
