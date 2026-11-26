package shim

import (
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// readOnlyTools are the tools that change nothing, so running one a second
// time is harmless: when the engine drops one mid-call (an upgrade restarted
// it), the shim sends it once more to the engine that comes back. Everything
// else (write, run_start, the revert tools) may have run and is never sent
// again.
var readOnlyTools = map[string]bool{
	guidance.ToolQuery:       true,
	guidance.ToolDescribe:    true,
	guidance.ToolListPending: true,
	guidance.ToolListRuns:    true,
	guidance.ToolRunHistory:  true,
	guidance.ToolStatus:      true,
}

// retriable reports whether line can be sent again after the engine dropped
// it without an answer: only a call of a read-only tool.
func retriable(line []byte) bool {
	req, ok := mcpserver.RequestOf(line)
	if !ok {
		return false
	}
	if req.Method != "tools/call" {
		return false
	}
	var p struct {
		Name string `json:"name"`
	}
	return json.Unmarshal(req.Params, &p) == nil && readOnlyTools[p.Name]
}
