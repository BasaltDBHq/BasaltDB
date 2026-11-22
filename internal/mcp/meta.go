package mcp

import (
	"context"
	"encoding/json"
)

// metaKey is the context key of a tools/call request's _meta.
type metaKey struct{}

// withMeta carries the _meta object of a tools/call request to the tool;
// a request without one carries nothing.
func withMeta(ctx context.Context, meta json.RawMessage) context.Context {
	if len(meta) == 0 {
		return ctx
	}
	return context.WithValue(ctx, metaKey{}, meta)
}

// Meta is the _meta object of the tools/call request ctx serves, nil when
// it had none. It is what the client (or basalt mcp, for the keys it owns)
// sent, so a tool trusts nothing in it that it cannot check.
func Meta(ctx context.Context) json.RawMessage {
	m, _ := ctx.Value(metaKey{}).(json.RawMessage)
	return m
}

// MetaPluginUpload is the _meta key under which basalt mcp hands the engine
// the plugin files it uploaded for a request_plugin call (CONTRACT.md, MCP
// tools, request_plugin).
const MetaPluginUpload = "dev.basaltdb/upload"

// PluginUpload is the value of MetaPluginUpload.
type PluginUpload struct {
	UploadID    string   `json:"uploadId"`
	Name        string   `json:"name"`
	Executables []string `json:"executables,omitempty"`
}
