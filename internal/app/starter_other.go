//go:build !unix

package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// EngineStarter: the engine runs on Linux and macOS only, so nothing starts.
func EngineStarter(engine.StarterHost, time.Duration, string, string, *config.Config, int, string, *slog.Logger) (func(context.Context) error, func() string) {
	return nil, nil
}
