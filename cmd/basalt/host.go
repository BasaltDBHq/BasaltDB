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
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/browser"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
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
	// dialog, to run script as root (service.DialogCommand), with a fixed
	// environment and / as its directory.
	AdminDialog(ctx context.Context, goos, script string, out io.Writer) error
	// LookPath finds a command on PATH.
	LookPath(name string) (string, error)
	// Run runs a command as the person.
	Run(ctx context.Context, args []string, out, errw io.Writer) error
	// System runs service install steps in this process (init as root).
	System(out, errw io.Writer) service.System
	// Probe waits until the engine answers MCP initialize on socket.
	Probe(ctx context.Context, socket string) error
	// EngineLog reads the end of the engine service's log on goos, when
	// the person may read it.
	EngineLog(ctx context.Context, goos string) (string, error)
	// OpenURL opens link in the person's default browser.
	OpenURL(ctx context.Context, link string) error
	// PagesUp reports whether the engine serves its local pages at origin.
	PagesUp(ctx context.Context, origin string) bool
	// IssueLink asks the engine's pages for a short link (POST .../links)
	// with proof of the item's binding text, and returns its url.
	IssueLink(ctx context.Context, endpoint, proof string) (string, error)
}

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
	paths, err := service.DialogPaths(goos)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (%s is missing)", service.ErrNoDialog, p)
		}
	}
	if goos != "darwin" {
		return nil
	}
	// The dialog shows on the Mac's screen: only for the person logged in there.
	uid, err := fileOwnerUID(darwinConsole)
	if err != nil {
		return fmt.Errorf("%w (%s: %w)", service.ErrNoDialog, darwinConsole, err)
	}
	if uid != os.Geteuid() {
		return fmt.Errorf("%w (you are not the user logged in at this Mac's screen)", service.ErrNoDialog)
	}
	return nil
}

// dialogEnv is the whole environment of the dialog program: nothing of the
// caller's reaches the script.
var dialogEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}

func (osHost) AdminDialog(ctx context.Context, goos, script string, out io.Writer) error {
	argv, err := service.DialogCommand(goos, script)
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
	return service.DialogError(goos, code, said.String(), err)
}

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

func (osHost) IssueLink(ctx context.Context, endpoint, proof string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, pagesProbeTimeout)
	defer cancel()
	body, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		URL     string `json:"url"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxLinkAnswer)).Decode(&out); err != nil {
		return "", fmt.Errorf("engine answered %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || out.URL == "" {
		return "", fmt.Errorf("engine answered %d: %s", resp.StatusCode, out.Message)
	}
	return out.URL, nil
}

// maxLinkAnswer bounds the engine's answer to a link request.
const maxLinkAnswer = 16 << 10

func (osHost) System(out, errw io.Writer) service.System {
	return service.OSSystem{Stdout: out, Stderr: errw}
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
		out, err := exec.CommandContext(ctx, "journalctl", "-u", service.SystemdUnitName,
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
