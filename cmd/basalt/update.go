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
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
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
// is the engine's own, 0600), the engine's answer decides, over the person
// socket; with no answer the check stays off, so an admin's opt-out is never
// overridden by a failed read. No config at all means nobody opted out.
func updateOff(ctx context.Context, getenv func(string) string, goos string, h host, askEngine func(context.Context) (person.PagesDTO, error)) bool {
	if updatecheck.Disabled(getenv) || buildinfo.Version == updatecheck.DevVersion {
		return true
	}
	cfg, err := loadEngineConfigAs(h.Euid(), perUserConfigFallback(h, config.DefaultPath(goos)))
	switch {
	case err == nil:
		return !cfg.UpdateCheckOn()
	case errors.Is(err, fs.ErrNotExist):
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, refreshGrace)
	defer cancel()
	pages, perr := askEngine(ctx)
	return perr != nil || pages.UpdateCheck != "ON"
}

func updateChecker(getenv func(string) string) (*updatecheck.Checker, error) {
	if buildinfo.Version == updatecheck.DevVersion {
		return nil, errDevBuild
	}
	dir, err := updatecheck.CacheDir(getenv(envCacheDir))
	if err != nil {
		return nil, err
	}
	return &updatecheck.Checker{Dir: dir, Current: buildinfo.Version}, nil
}

// errDevBuild means this build has no release number, so no check runs.
var errDevBuild = errors.New("a build with no release number gets no update notice")

// cachedUpdate is the notice for basalt status --json, from the cache only
// (the caller has checked that the check is on).
func cachedUpdate(c *cliIO) *updatecheck.Notice {
	ck, err := updateChecker(c.getenv)
	if err != nil {
		return nil
	}
	return ck.Cached()
}

// startUpdateNotice starts the refresh for a command and returns the
// function to call after it ran: it prints the notice. It does nothing for
// the commands in noUpdateLine and for --json (whose output carries the
// notice as a field where the command has one).
func startUpdateNotice(ctx context.Context, args []string, std stdio, getenv func(string) string) func() {
	nothing := func() {}
	if len(args) == 0 || slices.Contains(noUpdateLine, args[0]) || wantsJSON(args) {
		return nothing
	}
	if updateOff(ctx, getenv, runtime.GOOS, osHost{}, person.Client{Path: config.PersonSocketPath(config.DefaultSocketDir(runtime.GOOS))}.Pages) {
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
		printUpdateLine(std.err, getenv, ck.Cached(), exe)
	}
}

// printUpdateLine writes n's line to w: yellow, or red for a security
// release, only when w is a terminal and NO_COLOR is not set.
func printUpdateLine(w io.Writer, getenv func(string) string, n *updatecheck.Notice, exe string) {
	if n == nil {
		return
	}
	line := n.Line(exe)
	if getenv("NO_COLOR") == "" && isTerminal(w) {
		color := ansiYellow
		if n.Security {
			color = ansiRed
		}
		line = color + line + ansiReset
	}
	fmt.Fprintln(w, line)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// wantsJSON is true when args carry --json (or -json), with or without a value.
func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "-json" || strings.HasPrefix(a, "--json=") || strings.HasPrefix(a, "-json=") {
			return true
		}
	}
	return false
}
