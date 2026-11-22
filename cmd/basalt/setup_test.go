package main

import (
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

	service "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/config"
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
	sys       *fakeSys
	// probeErr is what Probe returns; engineLog what EngineLog reads.
	probeErr  error
	engineLog string
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

func (h *fakeHost) ResolvedExecutable() (string, error) { return fakeBin, nil }

func (h *fakeHost) DialogAvailable(string) error { return h.noDialog }

func (h *fakeHost) SetupState(context.Context, string) (string, error) {
	h.setupCalls++
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
	return h.dialogErr
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
	// existing are the files Exists finds (an installed unit).
	existing map[string]bool
}

func (s *fakeSys) UserExists(string) bool  { return false }
func (s *fakeSys) Exists(path string) bool { return s.existing[path] }
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

func me(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	return u.Username
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
