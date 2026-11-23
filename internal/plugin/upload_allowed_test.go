package plugin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// A plugin is uploaded for a person-operated engine with local pages, or
// for an agent-operated one; never for one that said neither.
func TestUploadAllowed(t *testing.T) {
	for _, c := range []struct {
		operatedBy, pagesOrigin string
		want                    bool
	}{
		{mcpcontract.OperatedByPerson, "http://127.0.0.1:8787", true},
		{mcpcontract.OperatedByPerson, "", false},
		{mcpcontract.OperatedByAgent, "", true},
		{mcpcontract.OperatedByAgent, "http://127.0.0.1:8787", true},
		{"", "http://127.0.0.1:8787", false},
		{"SOMEONE", "", false},
	} {
		require.Equal(t, c.want, plugin.UploadAllowed(c.operatedBy, c.pagesOrigin), "%q %q", c.operatedBy, c.pagesOrigin)
	}
}
