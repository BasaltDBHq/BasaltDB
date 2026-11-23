package enginecli

import (
	"context"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// RunService installs the engine as a system service, always on the
// system config path: it takes no --config, so the removal script's
// engine.json check (service.RemoveScript) is about the config it runs. It prints every
// step first; --dry-run stops there. The removal is the setup page's
// Remove, after which basalt init removes the service through the
// administrator dialog (service.RemoveScript).
func RunService(ctx context.Context, args []string, io cli.Stdio, h Host) int {
	return h.RunServiceAt(ctx, args, io, config.DefaultPath(runtime.GOOS))
}
