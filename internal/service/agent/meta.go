package agent

import (
	"context"
	"encoding/json"
)

// metaKey is the context key of a tools/call request's _meta.
type metaKey struct{}

// WithMeta carries the _meta object of a tools/call request to the tool
// that serves it; a request without one carries nothing. The inbound
// adapter calls it for every call it hands to a Tool.
func WithMeta(ctx context.Context, meta json.RawMessage) context.Context {
	if len(meta) == 0 {
		return ctx
	}
	return context.WithValue(ctx, metaKey{}, meta)
}

// metaOf is the _meta object of the request ctx serves, nil when it had
// none. It is what the client (or basalt mcp, for the keys it owns) sent,
// so a tool trusts nothing in it that it cannot check.
func metaOf(ctx context.Context) json.RawMessage {
	m, _ := ctx.Value(metaKey{}).(json.RawMessage)
	return m
}

// MetaPluginUpload is the _meta key under which basalt mcp hands the engine
// the plugin files it uploaded for a request_plugin call.
const MetaPluginUpload = "dev.basaltdb/upload"

// PluginUpload is the value of MetaPluginUpload.
type PluginUpload struct {
	UploadID    string   `json:"uploadId"`
	Name        string   `json:"name"`
	Executables []string `json:"executables,omitempty"`
}
