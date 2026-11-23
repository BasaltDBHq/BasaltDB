package plugin

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// The tests that upload through basalt mcp's uploader cannot import the
// shim: it imports this package. shim_uploader_test.go, in the external
// test package, hands the uploader and its no-uploads error over before the
// tests run.
var (
	newShimUploader  func(socketPath string) func(ctx context.Context, source string) (mcpserver.PluginUpload, error)
	errShimNoUploads error
)

// SetShimUploader is how shim_uploader_test.go hands them over.
func SetShimUploader(f func(socketPath string) func(ctx context.Context, source string) (mcpserver.PluginUpload, error), noUploads error) {
	newShimUploader, errShimNoUploads = f, noUploads
}
