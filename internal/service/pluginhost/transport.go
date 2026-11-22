package plugin

import "context"

// Transport carries one request to a plugin and decodes its reply. It is the
// only thing the host knows about how a plugin is reached.
//
// Call must honor ctx, return an error made with Fail when it knows the
// failure class (anything else counts as UNAVAILABLE), and never put request
// or response text in an error. It may be called from several goroutines.
// Close ends the connection and, for a local plugin, its process.
type Transport interface {
	Call(ctx context.Context, method string, params, result any) error
	Close() error
}
