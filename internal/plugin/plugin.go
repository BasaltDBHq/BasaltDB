// Package plugin is the protocol-neutral plugin host. It knows entries, the
// agents each entry serves and the shape of a call, and nothing about how
// bytes reach a plugin: transports are adapters behind the Transport
// interface and live in other packages.
package plugin

// Hook names a point in the engine where a plugin is called.
type Hook string

// The hooks. HookWireVerdict is reserved and refused.
const (
	HookWireDetect      Hook = "wire.detect"
	HookFeedObserve     Hook = "feed.observe"
	HookApprovalDeliver Hook = "approval.deliver"
	HookClassifySuggest Hook = "classify.suggest"
	HookWireVerdict     Hook = "wire.verdict"
)

// Allowed reports whether a manifest may declare the hook. The reserved
// wire.verdict and any unknown name are not allowed.
func (h Hook) Allowed() bool {
	return h == HookWireDetect || h == HookFeedObserve || h == HookApprovalDeliver || h == HookClassifySuggest
}
