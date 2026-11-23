package plugin_test

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// The internal tests upload through basalt mcp's real uploader: the plugin
// service's UploadFolder over the shim's channel. The shim imports this
// package, so it is handed over from here.
func init() {
	plugin.SetShimUploader(func(socketPath string) func(context.Context, string) (mcpserver.PluginUpload, error) {
		ch := shim.NewUploader(socketPath)
		return func(ctx context.Context, source string) (mcpserver.PluginUpload, error) {
			up, err := plugin.UploadFolder(ctx, ch, source)
			if err != nil {
				return mcpserver.PluginUpload{}, err
			}
			return mcpserver.PluginUpload{UploadID: up.UploadID, Name: up.Name, Executables: up.Executables}, nil
		}
	}, shim.ErrNoUploads)
}
