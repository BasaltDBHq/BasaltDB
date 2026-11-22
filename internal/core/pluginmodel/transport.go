package pluginmodel

import (
	"context"
	"errors"
)

// FailureClass says how a call failed, and nothing more.
type FailureClass string

// The failure classes.
const (
	ClassTimeout     FailureClass = "TIMEOUT"
	ClassExited      FailureClass = "EXITED"
	ClassBadResponse FailureClass = "BAD_RESPONSE"
	ClassOverLimit   FailureClass = "OVER_LIMIT"
	ClassUnavailable FailureClass = "UNAVAILABLE"
)

// CallError is a failed call to a plugin. It names the entry and the failure
// class only; it never carries a request, a response or a transport message.
type CallError struct {
	Entry EntryKey
	Class FailureClass
}

// Error implements error.
func (e *CallError) Error() string {
	return "plugin " + e.Entry.String() + ": " + string(e.Class)
}

// ErrAgentNotListed is returned, before any byte is sent, when a call names
// an agent the entry does not list. The error never names the agent.
var ErrAgentNotListed = errors.New("plugin: call names an agent the entry does not list")

// Classed is implemented by transport errors that know their failure class.
type Classed interface {
	error
	FailureClass() FailureClass
}

type classedError struct{ class FailureClass }

func (e classedError) Error() string              { return string(e.class) }
func (e classedError) FailureClass() FailureClass { return e.class }

// Fail returns the error a transport gives for a failure of the given class.
// The host turns it into a CallError for the entry. Transports must not wrap
// payload text into it.
func Fail(class FailureClass) error { return classedError{class} }

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
