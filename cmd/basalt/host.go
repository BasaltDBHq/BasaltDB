package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/lib/browser"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// host is what basalt init does on the machine beyond Postgres: elevate
// once with sudo for the service install, check the engine answers, and
// run claude mcp add. Tests replace it with a fake that records calls.
type host interface {
	// Euid is the effective user id (0 when init already runs as root).
	Euid() int
	// Executable is the absolute path of this basalt binary.
	Executable() (string, error)
	// UserConfigDir is the person's config directory (os.UserConfigDir).
	UserConfigDir() (string, error)
	// Sudo runs args under sudo with stdin, which carries the agent's
	// credential; sudo asks for the password on the terminal.
	Sudo(ctx context.Context, args []string, stdin string, out, errw io.Writer) error
	// ResolvedExecutable is this basalt binary's path with every link
	// resolved; an error when a link cannot be resolved.
	ResolvedExecutable() (string, error)
	// DialogAvailable says why the system's administrator dialog cannot be
	// shown here, or nil when it can (service.ErrNoDialog wrapped).
	DialogAvailable(goos string) error
	// AdminDialog asks the person, through the system's administrator
	// dialog showing prompt (one of service's fixed prompts), to run script
	// as root (service.DialogCommand), with a fixed environment and / as its
	// directory.
	AdminDialog(ctx context.Context, goos, prompt, script string, out io.Writer) error
	// SetupState posts an empty request to the engine's setup check route
	// at origin and returns the refusal code it answers: JOB_UNAVAILABLE
	// from an engine that has a config, another code from one waiting for
	// it. An error when nothing answers.
	SetupState(ctx context.Context, origin string) (string, error)
	// LookPath finds a command on PATH.
	LookPath(name string) (string, error)
	// Run runs a command as the person.
	Run(ctx context.Context, args []string, out, errw io.Writer) error
	// System runs service install steps in this process (init as root).
	System(out, errw io.Writer) system
	// Probe waits until the engine answers MCP initialize on socket.
	Probe(ctx context.Context, socket string) error
	// EngineLog reads the end of the engine service's log on goos, when
	// the person may read it.
	EngineLog(ctx context.Context, goos string) (string, error)
	// OpenURL opens link in the person's default browser.
	OpenURL(ctx context.Context, link string) error
	// PagesUp reports whether the engine serves its local pages at origin.
	PagesUp(ctx context.Context, origin string) bool
	// ServiceRuns reads from the service manager how many times the engine
	// service started and its last exit code (-1 when it never exited).
	ServiceRuns(ctx context.Context, goos string) (runs, lastExit int, err error)
}

// system is what the service install steps do on the machine: the
// operating system's users, groups and files, and the commands it runs. It
// has the method set of the service install's System, so either is the
// other.
type system interface {
	UserExists(name string) bool
	// InGroup reports whether an OS user is in a group, as its primary or a
	// supplementary group; a group that does not exist has no one in it.
	InGroup(name, group string) (bool, error)
	// Exists reports whether a file exists (an installed unit).
	Exists(path string) bool
	Output(ctx context.Context, args ...string) (string, error)
	Run(ctx context.Context, args ...string) error
	// WriteFile writes a file without following links; owner, when set, is
	// the OS user that owns the new file.
	WriteFile(path string, data []byte, mode os.FileMode, owner string) error
	// CreateFile makes an empty file owned by owner with mode when it is
	// missing and keeps an existing one's content, without following a
	// link; it refuses a path that is not a plain file.
	CreateFile(path string, mode os.FileMode, owner string) error
	// MoveAside renames the directory at path, as a whole and without
	// following a link, to a new name next to it when the OS user owner
	// owns it, and returns that name ("" when left as it is).
	MoveAside(path, owner string) (string, error)
	// Mkdir makes a directory (or takes over an existing real one) without
	// following a link; group, when set, is its group instead of owner's.
	Mkdir(path string, mode os.FileMode, owner, group string) error
	Remove(path string) error
	// RemoveTree removes a directory and everything in it without
	// following a link; a missing one is not an error.
	RemoveTree(path string) error
	// CheckBinary refuses a binary anyone but root could change.
	CheckBinary(path string) error
}

// appShell is the shell's real host: the adapters, reached through app.
type appShell struct{}

func (appShell) Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return app.Connect(ctx, dsn)
}

func (appShell) WithCertificateHint(dsn string, err error) error {
	return app.WithCertificateHint(dsn, err)
}

func (appShell) CertificateNotVerified(err error) bool { return app.CertificateNotVerified(err) }

func (appShell) CurrentTrustProfileSet() *trustprofile.Set { return app.CurrentTrustProfileSet() }

func (appShell) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return app.OSOpenTrustedFile(path, owner)
}

// appSetupHost is basalt init --remote's real host: the adapters, reached
// through app.
type appSetupHost struct{}

func (appSetupHost) GuardAgentConnString(adminURL, role, password string) (string, error) {
	return app.GuardAgentConnString(adminURL, role, password)
}

func (appSetupHost) GuardAgentVersion(ctx context.Context, q pgquerier.Querier) (int, error) {
	return app.GuardAgentVersion(ctx, q)
}

func (appSetupHost) GuardLatestVersion() int { return app.GuardLatestVersion() }

func (appSetupHost) GuardSetupRecorded(ctx context.Context, q pgquerier.Querier, id uuid.UUID) (bool, error) {
	return app.GuardSetupRecorded(ctx, q, id)
}

func (appSetupHost) LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return app.LoadOrCreateEngineKeys(path, now)
}

func (appSetupHost) TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return app.TrustProfileFor(configPath, host)
}

func (appSetupHost) OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error) {
	d, err := app.OSOpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (appSetupHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return app.OSOpenTrustedFile(path, owner)
}

func (appSetupHost) OSLookupUID(name string) int { return app.OSLookupUID(name) }

func (appSetupHost) OSInstallScript(goos, binary string) (string, error) {
	return app.OSInstallScript(goos, binary)
}

func (appSetupHost) OSRemoveScript(goos string) (string, error) { return app.OSRemoveScript(goos) }

func (appSetupHost) OSResetScript(goos string) (string, error) { return app.OSResetScript(goos) }

func (appSetupHost) OSDefaultUser(goos string) string { return app.OSDefaultUser(goos) }

func (appSetupHost) OSUnitPath(goos string) string { return app.OSUnitPath(goos) }

// osHost is the real machine.
type osHost struct{}

func (osHost) Euid() int                      { return os.Geteuid() }
func (osHost) Executable() (string, error)    { return shimExecutable() }
func (osHost) UserConfigDir() (string, error) { return os.UserConfigDir() }
func (osHost) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (osHost) ResolvedExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// darwinConsole is owned by the user logged in at the Mac's screen.
const darwinConsole = "/dev/console"

func (osHost) DialogAvailable(goos string) error {
	paths, err := app.OSDialogPaths(goos)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (%s is missing)", app.ErrOSNoDialog, p)
		}
	}
	if goos != "darwin" {
		return nil
	}
	// The dialog shows on the Mac's screen: only for the person logged in there.
	uid, err := cli.FileOwnerUID(darwinConsole)
	if err != nil {
		return fmt.Errorf("%w (%s: %w)", app.ErrOSNoDialog, darwinConsole, err)
	}
	if uid != os.Geteuid() {
		return fmt.Errorf("%w (you are not the user logged in at this Mac's screen)", app.ErrOSNoDialog)
	}
	return nil
}

// dialogEnv is the whole environment of the dialog program: nothing of the
// caller's reaches the script.
var dialogEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}

func (osHost) AdminDialog(ctx context.Context, goos, prompt, script string, out io.Writer) error {
	argv, err := app.OSDialogCommand(goos, prompt, script)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env, cmd.Dir = dialogEnv, "/"
	var said bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, io.MultiWriter(out, &said)
	err = cmd.Run()
	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	return app.OSDialogError(goos, code, said.String(), err)
}

func (osHost) SetupState(ctx context.Context, origin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+localsetup.SetupCheckPath, strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxLinkAnswer)).Decode(&out); err != nil {
		return "", fmt.Errorf("engine answered %d", resp.StatusCode)
	}
	return out.Code, nil
}

func (osHost) ServiceRuns(ctx context.Context, goos string) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	if goos == "darwin" {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+app.OSLaunchdLabel).Output()
		if err != nil {
			return 0, 0, err
		}
		return parseLaunchdRuns(string(out))
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "NRestarts", "-p", "ExecMainStatus", app.OSUnitName).Output()
	if err != nil {
		return 0, 0, err
	}
	return parseSystemdRuns(string(out))
}

// parseLaunchdRuns reads "runs = N" and "last exit code = N" (a code may
// carry its name after a colon, or be "(never exited)") from launchctl
// print.
func parseLaunchdRuns(out string) (runs, lastExit int, err error) {
	runs, lastExit = -1, -1
	for line := range strings.SplitSeq(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch {
		case k == "runs" && runs < 0:
			if runs, err = strconv.Atoi(v); err != nil {
				return 0, 0, fmt.Errorf("launchctl print: runs %q", v)
			}
		case k == "last exit code" && lastExit < 0:
			// "1", "78: EX_CONFIG" or "(never exited)".
			code, _, _ := strings.Cut(v, ":")
			if n, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				lastExit = n
			}
		}
	}
	if runs < 0 {
		return 0, 0, errors.New("launchctl print names no runs")
	}
	return runs, lastExit, nil
}

// parseSystemdRuns reads NRestarts and ExecMainStatus from systemctl show:
// the service started once more than it restarted.
func parseSystemdRuns(out string) (runs, lastExit int, err error) {
	restarts, status := -1, -1
	for line := range strings.SplitSeq(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		n, err := strconv.Atoi(v)
		switch {
		case k == "NRestarts" && err == nil:
			restarts = n
		case k == "ExecMainStatus" && err == nil:
			status = n
		}
	}
	if restarts < 0 {
		return 0, 0, errors.New("systemctl show names no NRestarts")
	}
	return restarts + 1, status, nil
}

// maxLinkAnswer bounds the engine's answer to a pages API request.
const maxLinkAnswer = 16 << 10

func (osHost) Sudo(ctx context.Context, args []string, stdin string, out, errw io.Writer) error {
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(stdin), out, errw
	return cmd.Run()
}

func (osHost) Run(ctx context.Context, args []string, out, errw io.Writer) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = out, errw
	return cmd.Run()
}

func (osHost) OpenURL(ctx context.Context, link string) error {
	return browser.Open(ctx, link)
}

// pagesProbeTimeout bounds the check that the engine serves its pages: a
// loopback answer is immediate.
const pagesProbeTimeout = 2 * time.Second

func (osHost) PagesUp(ctx context.Context, origin string) bool {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (osHost) System(out, errw io.Writer) system {
	return app.OSExecSystem{Stdout: out, Stderr: errw}
}

// Probe timing: a service manager starts the engine within seconds.
const (
	probeTimeout  = 20 * time.Second
	probeInterval = 500 * time.Millisecond
	probeIOLimit  = 2 * time.Second
)

func (osHost) Probe(ctx context.Context, socket string) error {
	deadline := time.Now().Add(probeTimeout)
	for {
		err := probeOnce(socket)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(probeInterval):
		}
	}
}

// engineLogTail is how much of the engine service's log init reads when
// the engine does not answer: its last start's lines.
const (
	engineLogTail      = 64 << 10
	engineJournalLines = "50"
)

func (osHost) EngineLog(ctx context.Context, goos string) (string, error) {
	if goos != "darwin" {
		out, err := exec.CommandContext(ctx, "journalctl", "-u", app.OSUnitName,
			"-n", engineJournalLines, "-o", "cat", "--no-pager").Output()
		return string(out), err
	}
	f, err := os.Open(darwinEngineLog)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if off := fi.Size() - engineLogTail; off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return "", err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, engineLogTail))
	return string(raw), err
}

// probeInit is the MCP initialize request the probe sends.
const probeInit = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"basalt-init","version":"0"}}}` + "\n"

// probeOnce connects to the agent's socket, sends initialize and checks
// the engine names itself.
func probeOnce(socket string) error {
	conn, err := net.DialTimeout("unix", socket, probeIOLimit)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeIOLimit)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, probeInit); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("no answer: %w", err)
	}
	if !strings.Contains(line, `"name":"basalt"`) {
		return errors.New("unexpected answer from the socket")
	}
	return nil
}
