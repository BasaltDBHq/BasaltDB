package shim

import (
	"encoding/json"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
)

// readOnlyTools are the tools that change nothing, so running one a second
// time is harmless: when the engine drops one mid-call (an upgrade restarted
// it), the shim sends it once more to the engine that comes back. Everything
// else (write, run_start, the revert tools) may have run and is never sent
// again.
var readOnlyTools = map[string]bool{
	"query":        true,
	"describe":     true,
	"list_pending": true,
	"list_runs":    true,
	"run_history":  true,
	"status":       true,
}

// retriable reports whether line can be sent again after the engine dropped
// it without an answer: only a call of a read-only tool.
func retriable(line []byte) bool {
	req, ok := mcp.RequestOf(line)
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
