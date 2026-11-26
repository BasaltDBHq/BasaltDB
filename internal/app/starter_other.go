//go:build !unix

package app

import (
	"context"
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// EngineStarter: the engine runs on Linux and macOS only, so nothing starts.
func (engineCLIHost) EngineStarter(string, string, *config.Config, int, string, *slog.Logger) (func(context.Context) error, func() string) {
	return nil, nil
}
