package plugin_test

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// The internal tests upload through basalt mcp's real uploader; it lives in
// the shim, which imports this package, so it is handed over from here.
func init() {
	plugin.SetShimUploader(func(socketPath string) func(context.Context, string) (mcpserver.PluginUpload, error) {
		return shim.NewPluginUploader(socketPath)
	}, shim.ErrNoUploads)
}
