package app

import (
	"net"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// restartOptions turn on the restart onto a new binary.
type restartOptions struct {
	// Restart is when the engine restarts (Upgrade; nil turns the restart
	// off) and how long it waits for calls (IdleWait, DrainWait).
	engine.Restart
	// Handoff reaches the connect service and the collected database for
	// a connect-only agent; the zero value is the contract's.
	Handoff handoffOptions
	// PagesListener, when set, is the pages' listener already bound at the
	// local pages address by an engine that waited for its config
	// (WaitForConfig): the engine serves its pages on it, so the port is
	// never free between the two. One the config does not use is closed.
	PagesListener net.Listener
	// StartedBy is why this engine started: "hand" (the default when
	// empty), "mcp" (basalt mcp found it down) or "crash" (the supervisor
	// restarted it). It is carried here for the status report.
	StartedBy string
	// StableAfter is how long the engine serves before it removes the
	// supervisor's record of giving up; zero means defaultStableAfter.
	StableAfter time.Duration
}

// defaultStableAfter is how long an engine serves before an earlier
// give-up of its supervisor is forgotten (last-stop.json is removed).
const defaultStableAfter = 10 * time.Second
