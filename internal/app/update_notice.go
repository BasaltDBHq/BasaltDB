package app

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/status"
	"github.com/basaltdbhq/basaltdb/internal/status/in/statuscli"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// The newer-release notice (CONTRACT.md, Update notice): every command but
// the long-running ones prints one line on stderr when a newer release is
// out. The line comes from a cache refreshed at most once a day; the
// refresh runs beside the command and the command waits for it only
// briefly, so an offline machine never stalls.

// appUpdateHost is the update check's status.Host and status.Terminal on
// the machine h, through app and the CLI shell.
type appUpdateHost struct{ h cli.Machine }

func (u appUpdateHost) UpdateDisabled(getenv func(string) string) bool {
	return updatecheck.Disabled(getenv)
}

func (u appUpdateHost) UpdateDevVersion() string { return updatecheck.DevVersion }

func (u appUpdateHost) Euid() int { return u.h.Euid() }

func (u appUpdateHost) DiscoverConfig(system string) (string, error) {
	return cli.DiscoverConfig(u.h, system)
}

func (u appUpdateHost) LoadEngineConfigAs(euid int, path string) (config.Config, error) {
	return cli.LoadEngineConfigAs(Shell{}, euid, path)
}

// noticeOf is n as the CLI prints it for the binary at exe; nil without a
// notice.
func noticeOf(n *updatecheck.Notice, exe string) *status.UpdateNotice {
	if n == nil {
		return nil
	}
	return &status.UpdateNotice{Line: n.Line(exe), Security: n.Security}
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

// StartUpdateNotice starts the refresh for a command and returns the
// function to call after it ran: it prints the notice. It does nothing for
// the commands in status.NoUpdateLine and for --json (whose output carries the
// notice as a field where the command has one).
func StartUpdateNotice(ctx context.Context, args []string, std cli.Stdio, getenv func(string) string) func() {
	nothing := func() {}
	if len(args) == 0 || slices.Contains(status.NoUpdateLine, args[0]) || cli.WantsJSON(args) {
		return nothing
	}
	if status.UpdateOff(getenv, appUpdateHost{OSHost{}}, appUpdateHost{OSHost{}}) {
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
		case <-time.After(status.RefreshGrace):
		}
		exe, _ := os.Executable()
		statuscli.PrintUpdateLine(std.Err, getenv, noticeOf(ck.Cached(), exe))
	}
}
