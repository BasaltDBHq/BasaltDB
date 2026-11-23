package pluginmodel

import "errors"

// Mode is how the engine runs. Its values are engine.json's mode values.
type Mode string

// Modes.
const (
	// ModeService: installed files and the trust store belong to root.
	ModeService Mode = "SERVICE"
	// ModeSameUser: they belong to the engine's own user, which is no
	// security boundary (CONTRACT.md, Plugins, Isolation and trust). An empty
	// mode is same-user, as in engine.json.
	ModeSameUser Mode = "SAME_USER"
)

// RootUID is the uid of root.
const RootUID = 0

// WhyGroupWritable is the path rule's refusal of a directory or file that
// its group or others can write.
const WhyGroupWritable = "can be written by group or others"

// WhyNotStickyRoot refuses a socket base, or a directory above it, that
// group or others can write and that is not root's with the sticky bit set.
const WhyNotStickyRoot = WhyGroupWritable + ", and is not a directory root owns with the sticky bit set"

// ErrUnknownMode is a mode other than SERVICE and SAME_USER.
var ErrUnknownMode = errors.New("plugin: unknown engine mode")

// The directory names under the base (service mode) or the config directory
// (same-user mode).
const (
	PluginsDirName = "plugins"
	TrustDirName   = "plugin-trust"
)

// PathRefusal is a path-rule failure. It names the path and the rule.
func PathRefusal(path, why string) *VerifyError {
	return &VerifyError{Reason: RefusedNotTrusted, File: path, Why: why}
}
