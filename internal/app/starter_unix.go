//go:build unix

package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

func osStarterDeps(wait time.Duration) engine.StarterDeps {
	return engine.StarterDeps{OS: engineos.OS{}, Owner: cli.PathOwner, Launch: engineos.LaunchDetached, Answers: engineos.SocketAnswers, Wait: wait, Now: time.Now}
}

// engineStarter is the starter basalt mcp gives the shim (see
// engine.NewStarter) with the real machine; wait is how long a start waits
// for the socket to answer.
func engineStarter(h engine.StarterHost, wait time.Duration, configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	return engine.NewStarter(h, osStarterDeps(wait), configPath, socket, cfg, euid, exe, log)
}
