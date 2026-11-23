package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/lib/browser"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

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

func (appSetupHost) ConnTarget(dsn string) (setupcli.ConnTarget, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setupcli.ConnTarget{}, err
	}
	return setupcli.ConnTarget{Host: cfg.Host, Port: int(cfg.Port), SystemRoots: cfg.TLSConfig != nil && cfg.TLSConfig.RootCAs == nil}, nil
}

func (appSetupHost) ServerMessage(err error) (string, bool) { return pgErrors{}.ServerMessage(err) }

func (appSetupHost) PathCredFiles() setup.CredFiles { return app.PathCredFiles{} }

func (h appSetupHost) OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error) {
	return openRootCredFiles(h, dir, trusted)
}

func (appSetupHost) RootTrustedOwner(dir string) (int, error) { return rootTrustedOwner(dir) }

func (h appSetupHost) OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error) {
	d, err := openRootConfigDir(h, dir, trusted)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (h appSetupHost) RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error) {
	d, _ := cfg.(*rootConfigDir)
	return rootEngineKey(h, stateDir, goos, d, now)
}

// setupFilesHost is how setup reaches the files root reads and writes for
// the engine's user: directories and files opened from / without following
// a link anyone but root or their owner controls, and OS user ids.
type setupFilesHost interface {
	// OSOpenTrustedDir opens dir for root, refusing a directory on the way
	// that someone other than root or owner could swap; create makes it
	// when missing.
	OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error)
	// OSOpenTrustedFile opens path read-only for root: its directory as
	// OSOpenTrustedDir does, the file itself never through a symlink.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
}

// trustedDir is a directory opened by OSOpenTrustedDir: files in it are
// reached relative to its descriptor, never by path. It is the credential
// files' own (app.TrustedDir), so a setupFilesHost reaches them too.
type trustedDir = app.TrustedDir

// osHost is the real machine.
type osHost struct{}

func (osHost) Euid() int                      { return os.Geteuid() }
func (osHost) Executable() (string, error)    { return cli.ShimExecutable() }
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

func (osHost) System(out, errw io.Writer) cli.System {
	return app.OSExecSystem{Stdout: out, Stderr: errw}
}

// Probe timing: a service manager starts the engine within seconds.
const (
	probeTimeout  = 20 * time.Second
	probeInterval = 500 * time.Millisecond
)

func (osHost) Probe(ctx context.Context, socket string) error {
	deadline := time.Now().Add(probeTimeout)
	for {
		err := cli.ProbeOnce(socket)
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
	f, err := os.Open(engine.DarwinEngineLog)
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
