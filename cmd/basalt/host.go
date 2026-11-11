package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

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
	// LookPath finds a command on PATH.
	LookPath(name string) (string, error)
	// Run runs a command as the person.
	Run(ctx context.Context, args []string, out, errw io.Writer) error
	// System runs service install steps in this process (init as root).
	System(out, errw io.Writer) service.System
	// Probe waits until the engine answers MCP initialize on socket.
	Probe(ctx context.Context, socket string) error
	// OpenURL opens link in the person's default browser.
	OpenURL(ctx context.Context, link string) error
}

// osHost is the real machine.
type osHost struct{}

func (osHost) Euid() int                      { return os.Geteuid() }
func (osHost) Executable() (string, error)    { return binaryPath("") }
func (osHost) UserConfigDir() (string, error) { return os.UserConfigDir() }
func (osHost) LookPath(name string) (string, error) {
	return exec.LookPath(name)
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
	name, ok := browserOpener(runtime.GOOS)
	if !ok {
		return fmt.Errorf("no browser opener on %s", runtime.GOOS)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s not found", name)
	}
	// The link is one argument, never passed through a shell.
	return exec.CommandContext(ctx, path, link).Run()
}

// browserOpener is the command that opens a URL in the default browser on
// goos.
func browserOpener(goos string) (string, bool) {
	switch goos {
	case "darwin":
		return "open", true
	case "linux":
		return "xdg-open", true
	}
	return "", false
}

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
