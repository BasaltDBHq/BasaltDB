//go:build !unix

package main

import (
	"context"
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// engineStarter: the engine runs on Linux and macOS only, so nothing starts.
func engineStarter(string, *config.Config, int, string, *slog.Logger) (func(context.Context) error, func() string) {
	return nil, nil
}
