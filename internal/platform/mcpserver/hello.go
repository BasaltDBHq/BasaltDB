package mcpserver

import (
	"encoding/json"
	"fmt"
)

// Protocol versions of the link between `basalt mcp` (the shim) and the
// engine. The version is an integer, raised only when a change would make
// an older shim or engine misbehave (CONTRACT.md, Version negotiation). A
// peer that does not say a version, because it predates the negotiation,
// is version 0.
const (
	// ShimProtocol is the version this build speaks.
	ShimProtocol = 1
	// MinShimProtocol is the oldest shim this build's engine serves.
	MinShimProtocol = 0
	// MinEngineProtocol is the oldest engine this build's shim works with.
	MinEngineProtocol = 0
)

// HelloMethod is the request the shim sends first on every connection to
// the engine; HelloID is its id, so the shim can tell its answer from the
// client's.
const (
	HelloMethod = "basalt/hello"
	HelloID     = "basalt-hello"
)

// ErrCodeVersionMismatch is the JSON-RPC error code of an answer that
// refuses a request because the shim and the engine do not agree on a
// protocol version.
const ErrCodeVersionMismatch = -32002

// Hello is the params of the hello request and the result of its answer.
// The shim sends Protocol and Build; the engine answers with its own
// Protocol and Build and the oldest shim it serves.
type Hello struct {
	Protocol        int    `json:"protocol"`
	Build           string `json:"build"`
	MinShimProtocol *int   `json:"minShimProtocol,omitempty"`
	// OperatedBy and PagesOrigin are in the engine's answer only: who runs
	// its machine steps (PERSON or AGENT), and the origin of the local pages
	// it serves ("" when it serves none). The shim opens a link on that
	// origin only when the engine says PERSON (CONTRACT.md, Auto-open).
	OperatedBy  string `json:"operatedBy,omitempty"`
	PagesOrigin string `json:"pagesOrigin,omitempty"`
}

type helloRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  Hello  `json:"params"`
}

// HelloLine is the hello request line for a shim of the given build.
func HelloLine(build string) []byte {
	raw, err := json.Marshal(helloRequest{JSONRPC: "2.0", ID: HelloID, Method: HelloMethod, Params: Hello{Protocol: ShimProtocol, Build: build}})
	if err != nil {
		panic(err) // a fixed struct of strings and ints
	}
	return append(raw, '\n')
}

// HelloAnswer decodes line as the answer to a hello; ok is false for any
// other line. An engine from before the negotiation answers method not
// found, which is version 0. known is false when the answer says nothing
// about the engine's version (the engine refused this shim with
// ErrCodeVersionMismatch, or failed in another way).
func HelloAnswer(line []byte) (h Hello, known, ok bool) {
	var r struct {
		ID     any             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if json.Unmarshal(line, &r) != nil || r.ID != HelloID {
		return Hello{}, false, false
	}
	if r.Error != nil {
		return Hello{}, r.Error.Code == rpcErrMethodNotFound, true
	}
	if json.Unmarshal(r.Result, &h) != nil {
		return Hello{}, false, true
	}
	return h, true, true
}

// ShimTooOldMessage is what an agent is told when its shim is older than
// the engine serves.
func ShimTooOldMessage(shim, engine Hello, need int) string {
	return fmt.Sprintf("this basalt mcp (build %s, protocol %d) is too old for the basalt engine (build %s), which needs protocol %d or newer. "+
		"BasaltDB was upgraded while this MCP server was running. Reconnect the MCP server so the client starts the upgraded `basalt mcp` "+
		"(in Claude Code run /mcp and reconnect basalt, or restart the agent client), then call again. Nothing was run for this call",
		orUnknown(shim.Build), shim.Protocol, orUnknown(engine.Build), need)
}

// EngineTooOldMessage is what an agent is told when its engine is older
// than the shim needs.
func EngineTooOldMessage(shim, engine Hello, need int) string {
	return fmt.Sprintf("the basalt engine (build %s, protocol %d) is older than this basalt mcp (build %s), which needs protocol %d or newer. "+
		"The engine was not restarted after BasaltDB was upgraded. Ask the person to restart the basalt engine (or its service) so it runs "+
		"the installed version, then call again",
		orUnknown(engine.Build), engine.Protocol, orUnknown(shim.Build), need)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
