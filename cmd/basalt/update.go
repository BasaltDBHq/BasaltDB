package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// The newer-release notice (CONTRACT.md, Update notice): every command but
// the long-running ones prints one line on stderr when a newer release is
// out. The line comes from a cache refreshed at most once a day; the
// refresh runs beside the command and the command waits for it only
// briefly, so an offline machine never stalls.

const (
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
	// refreshGrace is the longest a finished command waits for the refresh.
	refreshGrace = time.Second
)

// noUpdateLine are the commands that print no notice: the engine and the
// MCP server run for long and tell agents through MCP, help is a page.
var noUpdateLine = []string{"engine", "mcp", "help", "-h", "--help"}

// updateOff reports whether the check is turned off: the environment, or
// updateCheck OFF in the config a command would read by default. When that
// config exists but this person cannot read it (service mode: engine.json
// is the engine's own, 0600), the check stays off, so an admin's opt-out is
// never overridden by a failed read; the engine's own notice reaches the
// agent. No config at all means nobody opted out.
func updateOff(getenv func(string) string, h updateHost) bool {
	if h.UpdateDisabled(getenv) || buildinfo.Version == h.UpdateDevVersion() {
		return true
	}
	path, derr := h.DiscoverConfig(config.DefaultPath(runtime.GOOS))
	if derr != nil {
		// Two configs: the command itself reports it; the system one decides.
		path = config.DefaultPath(runtime.GOOS)
	}
	cfg, err := h.LoadEngineConfigAs(h.Euid(), path)
	switch {
	case err == nil:
		return !cfg.UpdateCheckOn()
	case errors.Is(err, fs.ErrNotExist):
		return false
	}
	return true
}

// updateHost is what updateOff reads outside itself: the environment's off
// switch, the version of a build with no release number, and the engine
// config a command would read by default.
type updateHost interface {
	// UpdateDisabled reports whether the environment turns the check off.
	UpdateDisabled(getenv func(string) string) bool
	// UpdateDevVersion is the version of a build with no release number.
	UpdateDevVersion() string
	// Euid is the effective user id.
	Euid() int
	// DiscoverConfig is the engine.json a command finds by itself, system
	// being the system path.
	DiscoverConfig(system string) (string, error)
	// LoadEngineConfigAs reads the engine config at path for a process
	// with effective uid euid.
	LoadEngineConfigAs(euid int, path string) (config.Config, error)
}

// appUpdateHost is updateHost on the machine h, through app.
type appUpdateHost struct{ h host }

func (u appUpdateHost) UpdateDisabled(getenv func(string) string) bool {
	return app.UpdateDisabled(getenv)
}

func (u appUpdateHost) UpdateDevVersion() string { return app.UpdateDevVersion }

func (u appUpdateHost) Euid() int { return u.h.Euid() }

func (u appUpdateHost) DiscoverConfig(system string) (string, error) {
	return discoverConfig(u.h, system)
}

func (u appUpdateHost) LoadEngineConfigAs(euid int, path string) (config.Config, error) {
	cfg, err := loadEngineConfigAs(appShell{}, euid, path)
	return cfg.Config, err
}

// updateNotice is the newer-release notice as the CLI prints it: its line
// and whether the newer release is a security fix.
type updateNotice struct {
	line     string
	security bool
}

// noticeOf is n as the CLI prints it for the binary at exe; nil without a
// notice.
func noticeOf(n *app.UpdateNotice, exe string) *updateNotice {
	if n == nil {
		return nil
	}
	return &updateNotice{line: n.Line(exe), security: n.Security}
}

func updateChecker(getenv func(string) string) (*app.UpdateChecker, error) {
	if buildinfo.Version == app.UpdateDevVersion {
		return nil, errDevBuild
	}
	dir, err := app.UpdateCacheDir(getenv(envCacheDir))
	if err != nil {
		return nil, err
	}
	return &app.UpdateChecker{Dir: dir, Current: buildinfo.Version}, nil
}

// errDevBuild means this build has no release number, so no check runs.
var errDevBuild = errors.New("a build with no release number gets no update notice")

// startUpdateNotice starts the refresh for a command and returns the
// function to call after it ran: it prints the notice. It does nothing for
// the commands in noUpdateLine and for --json (whose output carries the
// notice as a field where the command has one).
func startUpdateNotice(ctx context.Context, args []string, std stdio, getenv func(string) string) func() {
	nothing := func() {}
	if len(args) == 0 || slices.Contains(noUpdateLine, args[0]) || cli.WantsJSON(args) {
		return nothing
	}
	if updateOff(getenv, appUpdateHost{osHost{}}) {
		return nothing
	}
	ck, err := updateChecker(getenv)
	if err != nil {
		return nothing
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ck.Refresh(ctx) // a failed refresh is silent: the notice is a courtesy
	}()
	return func() {
		select {
		case <-done:
		case <-time.After(refreshGrace):
		}
		exe, _ := os.Executable()
		printUpdateLine(std.err, getenv, noticeOf(ck.Cached(), exe))
	}
}

// printUpdateLine writes n's line to w: yellow, or red for a security
// release, only when w is a terminal and NO_COLOR is not set.
func printUpdateLine(w io.Writer, getenv func(string) string, n *updateNotice) {
	if n == nil {
		return
	}
	line := n.line
	if getenv("NO_COLOR") == "" && cli.IsTerminal(w) {
		color := ansiYellow
		if n.security {
			color = ansiRed
		}
		line = color + line + ansiReset
	}
	fmt.Fprintln(w, line)
}
