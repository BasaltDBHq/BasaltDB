package app

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

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/browser"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// goosDarwin is runtime.GOOS on macOS.
const goosDarwin = "darwin"

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
	paths, err := osservice.DialogPaths(goos)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (%s is missing)", servicespec.ErrNoDialog, p)
		}
	}
	if goos != goosDarwin {
		return nil
	}
	// The dialog shows on the Mac's screen: only for the person logged in there.
	uid, err := cli.FileOwnerUID(darwinConsole)
	if err != nil {
		return fmt.Errorf("%w (%s: %w)", servicespec.ErrNoDialog, darwinConsole, err)
	}
	if uid != os.Geteuid() {
		return fmt.Errorf("%w (you are not the user logged in at this Mac's screen)", servicespec.ErrNoDialog)
	}
	return nil
}

// dialogEnv is the whole environment of the dialog program: nothing of the
// caller's reaches the script.
var dialogEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}

func (osHost) AdminDialog(ctx context.Context, goos, prompt, script string, out io.Writer) error {
	argv, err := osservice.DialogCommand(goos, prompt, script)
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
	return osservice.DialogError(goos, code, said.String(), err)
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

func (osHost) EngineBuild(ctx context.Context, origin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/healthz", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("engine answered %d", resp.StatusCode)
	}
	return resp.Header.Get(pageserver.BuildHeader), nil
}

func (osHost) ServiceRuns(ctx context.Context, goos string) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	if goos == goosDarwin {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+servicespec.LaunchdLabel).Output()
		if err != nil {
			return 0, 0, err
		}
		return parseLaunchdRuns(string(out))
	}
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "NRestarts", "-p", "ExecMainStatus", servicespec.SystemdUnitName).Output()
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
	return osservice.OSSystem{Stdout: out, Stderr: errw}
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
	if goos != goosDarwin {
		out, err := exec.CommandContext(ctx, "journalctl", "-u", servicespec.SystemdUnitName,
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
