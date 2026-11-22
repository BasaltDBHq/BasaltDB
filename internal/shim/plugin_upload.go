package shim

import (
	"context"
	"encoding/json"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// toolRequestPlugin is the one tool whose call the shim touches: it reads
// the plugin folder the call names and hands the engine the upload
// (CONTRACT.md, MCP tools, request_plugin). The engine never opens the
// agent's path itself.
const toolRequestPlugin = "request_plugin"

// PluginUploader reads the plugin folder source as this process's OS user
// and uploads it to the engine. It returns ErrNoUploads when the engine
// takes none, and a *mcp.ToolError for an answer the agent gets as it is.
type PluginUploader func(ctx context.Context, source string) (mcp.PluginUpload, error)

// prepare is line as the engine gets it: for a request_plugin call, any
// upload the client named is removed, and with source the shim's own
// upload is added, on a session whose engine said a person operates it and
// gave its local pages. answered is true when the shim answered the call
// itself (the folder could not be read or uploaded): nothing is sent.
func (r *relay) prepare(ctx context.Context, sess *session, line []byte) (out []byte, answered bool) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(line, &msg) != nil || stringOf(msg["method"]) != "tools/call" {
		return line, false
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(msg["params"], &params) != nil || stringOf(params["name"]) != toolRequestPlugin {
		return line, false
	}
	meta := map[string]json.RawMessage{}
	if raw, ok := params["_meta"]; ok && json.Unmarshal(raw, &meta) != nil {
		// Not an object: the engine refuses what it cannot read, and it
		// carries no upload.
		meta = map[string]json.RawMessage{}
	}
	delete(meta, mcp.MetaPluginUpload)
	var args struct {
		Source string `json:"source"`
	}
	_ = json.Unmarshal(params["arguments"], &args)
	if args.Source != "" && r.upload != nil && sess.uploadsPlugins() {
		up, err := r.upload(ctx, args.Source)
		var te *mcp.ToolError
		switch {
		case err == nil:
			raw, merr := json.Marshal(up)
			if merr == nil {
				meta[mcp.MetaPluginUpload] = raw
			}
		case asToolError(err, &te):
			if req, ok := mcp.RequestOf(line); ok {
				_ = mcp.WriteToolError(r.out, req.ID, te)
			}
			return nil, true
		}
		// Any other error (the engine takes no uploads): forward without one,
		// and the engine says why it cannot take the plugin.
	}
	if len(meta) == 0 {
		delete(params, "_meta")
	} else if raw, err := json.Marshal(meta); err == nil {
		params["_meta"] = raw
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return line, false
	}
	msg["params"] = rawParams
	rebuilt, err := json.Marshal(msg)
	if err != nil {
		return line, false
	}
	return rebuilt, false
}

// stringOf is raw as a JSON string, "" when it is not one: an escaped
// spelling reads as the name it spells, as the engine reads it.
func stringOf(raw json.RawMessage) string {
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v
}

func asToolError(err error, te **mcp.ToolError) bool {
	t, ok := err.(*mcp.ToolError) //nolint:errorlint // the uploader returns it unwrapped
	if ok {
		*te = t
	}
	return ok
}

// uploadsPlugins reports whether the engine said in its hello answer that a
// person operates it and gave its local page origin, or that an agent
// operates it (its approval link is the portal's): only then is a plugin
// uploaded for it. An engine that has not answered the hello yet gets none.
func (s *session) uploadsPlugins() bool {
	t := time.NewTimer(helloWait)
	defer t.Stop()
	select {
	case <-s.ready:
	case <-t.C:
		return false
	}
	switch s.engine.OperatedBy {
	case mcpcontract.OperatedByPerson:
		return s.engine.PagesOrigin != ""
	case mcpcontract.OperatedByAgent:
		return true
	}
	return false
}
