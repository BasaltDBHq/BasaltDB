// Package plugin is the protocol-neutral plugin host. It knows entries, the
// agents each entry serves and the shape of a call, and nothing about how
// bytes reach a plugin: transports are adapters behind the Transport
// interface and live in other packages.
package plugin

import (
	"encoding/json"
	"errors"
	"time"

	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

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

// EntryKey identifies a plugin entry. Two entries of one plugin differ in
// Instance and share nothing.
type EntryKey struct {
	Name     string
	Instance string
}

// String is "name/instance". It is safe to log.
func (k EntryKey) String() string { return k.Name + "/" + k.Instance }

// LocalEndpoint is a plugin the engine starts on this machine.
type LocalEndpoint struct {
	Transport string   `json:"transport"`
	Command   string   `json:"command"`
	Args      []string `json:"args,omitempty"`
}

// RemoteEndpoint is a plugin that runs elsewhere, reached over ConnectRPC.
type RemoteEndpoint struct {
	Transport string `json:"transport"`
	URL       string `json:"url"`
}

// Endpoint is exactly one of Local and Remote.
type Endpoint struct {
	Local  *LocalEndpoint  `json:"local,omitempty"`
	Remote *RemoteEndpoint `json:"remote,omitempty"`
}

// IsRemote reports whether the endpoint is a remote one.
func (e Endpoint) IsRemote() bool { return e.Remote != nil }

// Network is a manifest's declared egress.
type Network struct {
	Egress []string `json:"egress"`
}

// Resources are a manifest's optional resource hints.
type Resources struct {
	MemoryMB int `json:"memoryMB,omitempty"`
}

// Manifest is a plugin's basalt-plugin.json. Unknown fields are ignored.
type Manifest struct {
	ManifestVersion int                          `json:"manifestVersion"`
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	Publisher       string                       `json:"publisher"`
	Description     string                       `json:"description,omitempty"`
	Protocol        []string                     `json:"protocol"`
	Hooks           map[string]protocol.HookDecl `json:"hooks"`
	Endpoint        Endpoint                     `json:"endpoint"`
	Files           map[string]string            `json:"files,omitempty"`
	Network         Network                      `json:"network"`
	Resources       *Resources                   `json:"resources,omitempty"`
}

// Entry is one configured plugin: a manifest, the agents it serves, and its
// settings from engine.json.
type Entry struct {
	Key      EntryKey
	Manifest Manifest
	// Agents are the only agents this entry may be called for.
	Agents []string
	// Timeout is each call's deadline. Zero means the default for the
	// endpoint: 300 ms local, 2 s remote.
	Timeout time.Duration
	// Config is the entry's config object, sent to the plugin in initialize.
	Config json.RawMessage
}

// Timeout bounds and defaults.
const (
	MinTimeout           = 50 * time.Millisecond
	MaxTimeout           = 60 * time.Second
	DefaultLocalTimeout  = 300 * time.Millisecond
	DefaultRemoteTimeout = 2 * time.Second
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
