package handoff

import (
	"context"
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// ErrNoEngineKey is a collect while the engine key file is refused: the
// request cannot be signed.
var ErrNoEngineKey = errors.New("the engine key file is refused (vault.state KEY_ERROR): the address cannot be collected until it is fixed")

// RootCollector is the collector of an engine started as root: root trusts nothing the agent's OS user could redirect, and the
// YES would write that user's credential, so it never collects. The agent
// is served degraded with the problem ENGINE_AS_ROOT; the engine's other
// agents are served as usual.
type RootCollector struct{}

// Collect refuses: an engine started as root never collects.
func (RootCollector) Collect(context.Context, string, string) (Collected, error) {
	return Collected{}, ErrEngineAsRoot
}

// Report refuses: an engine started as root never collects.
func (RootCollector) Report(context.Context, string, string, setupcode.Address, Reach) error {
	return ErrEngineAsRoot
}

// NoKeyCollector is the collector of an engine whose key file is refused:
// it cannot sign a collect.
type NoKeyCollector struct{}

// Collect refuses: the request cannot be signed.
func (NoKeyCollector) Collect(context.Context, string, string) (Collected, error) {
	return Collected{}, ErrNoEngineKey
}

// Report refuses: the request cannot be signed.
func (NoKeyCollector) Report(context.Context, string, string, setupcode.Address, Reach) error {
	return ErrNoEngineKey
}
