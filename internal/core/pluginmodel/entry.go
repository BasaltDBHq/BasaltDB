// Package pluginmodel holds the plugin host's data types and the path rule:
// what an entry, a manifest, a verified copy and a transport call are. The
// host, the transports and the OS service adapter all share them, so none
// of them has to import another.
package pluginmodel

import (
	"encoding/json"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// DefaultInstance is an entry's instance when engine.json names none.
const DefaultInstance = "default"

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
	ManifestVersion int                             `json:"manifestVersion"`
	Name            string                          `json:"name"`
	Version         string                          `json:"version"`
	Publisher       string                          `json:"publisher"`
	Description     string                          `json:"description,omitempty"`
	Protocol        []string                        `json:"protocol"`
	Hooks           map[string]pluginproto.HookDecl `json:"hooks"`
	Endpoint        Endpoint                        `json:"endpoint"`
	Files           map[string]string               `json:"files,omitempty"`
	Network         Network                         `json:"network"`
	Resources       *Resources                      `json:"resources,omitempty"`
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
