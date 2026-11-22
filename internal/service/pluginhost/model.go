package pluginhost

import (
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// The plugin data types live in core/pluginmodel, so the transports and the
// OS service adapter can use them without importing the host. These aliases
// keep the host's other importers unchanged.
type (
	EntryKey       = pluginmodel.EntryKey
	LocalEndpoint  = pluginmodel.LocalEndpoint
	RemoteEndpoint = pluginmodel.RemoteEndpoint
	Endpoint       = pluginmodel.Endpoint
	Network        = pluginmodel.Network
	Resources      = pluginmodel.Resources
	Manifest       = pluginmodel.Manifest
	Entry          = pluginmodel.Entry
	FailureClass   = pluginmodel.FailureClass
	CallError      = pluginmodel.CallError
	Classed        = pluginmodel.Classed
	Transport      = pluginmodel.Transport
	Refusal        = pluginmodel.Refusal
	VerifyError    = pluginmodel.VerifyError
	PathFaultKind  = pluginmodel.PathFaultKind
	PathFault      = pluginmodel.PathFault
	Verified       = pluginmodel.Verified
	SignerState    = pluginmodel.SignerState
	Mode           = pluginmodel.Mode
)

// Timeout bounds and defaults, and the default instance.
const (
	MinTimeout           = pluginmodel.MinTimeout
	MaxTimeout           = pluginmodel.MaxTimeout
	DefaultLocalTimeout  = pluginmodel.DefaultLocalTimeout
	DefaultRemoteTimeout = pluginmodel.DefaultRemoteTimeout
	DefaultInstance      = pluginmodel.DefaultInstance
)

// The failure classes.
const (
	ClassTimeout     = pluginmodel.ClassTimeout
	ClassExited      = pluginmodel.ClassExited
	ClassBadResponse = pluginmodel.ClassBadResponse
	ClassOverLimit   = pluginmodel.ClassOverLimit
	ClassUnavailable = pluginmodel.ClassUnavailable
)

// The refusals, path faults, signer states, modes and path-rule names.
const (
	RefusedBadManifest = pluginmodel.RefusedBadManifest
	RefusedNotTrusted  = pluginmodel.RefusedNotTrusted
	PathWritable       = pluginmodel.PathWritable
	PathSymlink        = pluginmodel.PathSymlink
	PathOwner          = pluginmodel.PathOwner
	SignerKnown        = pluginmodel.SignerKnown
	SignerUnknown      = pluginmodel.SignerUnknown
	ModeService        = pluginmodel.ModeService
	ModeSameUser       = pluginmodel.ModeSameUser
	PluginsDirName     = pluginmodel.PluginsDirName
	TrustDirName       = pluginmodel.TrustDirName
	WhyGroupWritable   = pluginmodel.WhyGroupWritable
	WhyNotStickyRoot   = pluginmodel.WhyNotStickyRoot
	rootUID            = pluginmodel.RootUID
)

// ErrAgentNotListed is returned, before any byte is sent, when a call names
// an agent the entry does not list.
var ErrAgentNotListed = pluginmodel.ErrAgentNotListed

var errUnknownMode = pluginmodel.ErrUnknownMode

// Fail returns the error a transport gives for a failure of the given class.
func Fail(class FailureClass) error { return pluginmodel.Fail(class) }
