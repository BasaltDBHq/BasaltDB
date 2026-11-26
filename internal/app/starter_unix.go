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
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
)

func osStarterDeps(wait time.Duration) engine.StarterDeps {
	return engine.StarterDeps{OS: engineos.OS{}, Owner: cli.PathOwner, Launch: engineos.LaunchDetached, Answers: engineos.SocketAnswers, Wait: wait, Now: time.Now}
}

// EngineStarter is the starter basalt mcp gives the shim (engine.NewStarter)
// with the real machine, waiting shim.DefaultStartWait for the socket to
// answer.
func (engineCLIHost) EngineStarter(configPath, socket string, cfg *config.Config, euid int, exe string, log *slog.Logger) (start func(context.Context) error, failure func() string) {
	return engine.NewStarter(engineHost{}, osStarterDeps(shim.DefaultStartWait), configPath, socket, cfg, euid, exe, log)
}
