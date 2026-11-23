//go:build !unix

// On unix, plugins_internal_test.go holds TestMain: it installs the same
// path rule and also serves as a test plugin.

package plugin

import (
	"os"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/plugin/out/pluginpath"
)

// The path rule is a port the app fills; the tests fill it with the real one.
func TestMain(m *testing.M) {
	UsePathRules(pluginpath.Rules{})
	os.Exit(m.Run())
}
