package pluginmcp

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
)

// testErrors tells apart the adapters' error values as the engine does.
func testErrors() guidance.ErrorMap {
	return guidance.ErrorMap{
		InvalidParams: ledger.ErrInvalidParams,
		InvalidIntent: guard.ErrInvalidIntent,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
	}
}

const casePluginApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000e5"

// Exactly one form per call; no argument carries a signature, a code or
// settings. The controller refuses a call that breaks this before the plugin
// use case is asked anything.
func TestRequestPluginArguments(t *testing.T) {
	t.Parallel()
	for _, args := range []map[string]any{
		{},
		{"source": "/p", "name": "local-ner"},
		{"name": "local-ner", "approvalId": casePluginApproval},
		{"approvalId": casePluginApproval, "instance": "x"},
		{"approvalId": casePluginApproval, "remove": false},
		{"name": "local-ner", "waitForApproval": 5},
		{"source": "/p", "remove": true},
		{"name": "local-ner", "remove": true, "agents": []string{"bot"}},
		{"source": "relative/path"},
		{"approvalId": casePluginApproval, "signature": "basalt-plugin.1.x"},
		{"source": "/p", "settings": map[string]any{"config": map[string]any{}}},
		{"source": "/p", "config": map[string]any{}},
		{"source": "/p", "auth": map[string]any{}},
	} {
		raw, err := json.Marshal(args)
		require.NoError(t, err)
		var a requestPluginArgs
		err = guidance.DecodeArgs(raw, &a)
		if err == nil {
			err = a.check()
		}
		te := testErrors().ToolError(err)
		require.Equal(t, guidance.CodeInvalidArgument, te.Code, te.Message)
		require.Empty(t, te.Reason, "%v", args)
	}
}
