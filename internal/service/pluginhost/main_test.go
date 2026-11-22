package pluginhost

import (
	"os"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/pluginpath"
)

// The path rule is a port the app fills; the tests fill it with the real one.
func TestMain(m *testing.M) {
	UsePathRules(pluginpath.Rules{})
	os.Exit(m.Run())
}
