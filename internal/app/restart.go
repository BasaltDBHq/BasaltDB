package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// RestartOptions turn on the restart onto a new binary.
type RestartOptions struct {
	// Restart is when the engine restarts (Upgrade; nil turns the restart
	// off) and how long it waits for calls (IdleWait, DrainWait).
	engine.Restart
	// Handoff reaches the connect service and the collected database for
	// a connect-only agent; the zero value is the contract's.
	Handoff HandoffOptions
	// PluginStderr is where local plugins' stderr goes (basalt engine
	// --plugin-debug), on a foreground engine only; nil discards it. It
	// rides along with the restart options because both are how
	// basalt engine runs this engine.
	PluginStderr io.Writer
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
	// supervisor's record of giving up; zero means DefaultStableAfter.
	StableAfter time.Duration
}

// DefaultStableAfter is how long an engine serves before an earlier
// give-up of its supervisor is forgotten (last-stop.json is removed).
const DefaultStableAfter = 10 * time.Second

// LastStopFile is the supervisor's record of giving up, in the state
// directory (basalt engine --supervise).
const LastStopFile = "last-stop.json"

// startedByOrHand is v, or "hand" when empty.
func startedByOrHand(v string) string {
	if v == "" {
		return "hand"
	}
	return v
}

// gatedDispatcher counts each page-session request (an approval or a revert
// relayed through the Vault) in the gate, and answers UNAVAILABLE with
// nothing run once the gate is closed.
type gatedDispatcher struct {
	gate engine.Gate
	next vault.Dispatcher
}

func (d gatedDispatcher) Dispatch(ctx context.Context, link vault.SessionLink, req vault.Request) vault.Response {
	if !d.gate.Begin() {
		return restartingResponse()
	}
	defer d.gate.End()
	return d.next.Dispatch(ctx, link, req)
}

// restartingResponse is the pages API's error for a request the engine did
// not run because it is restarting.
func restartingResponse() vault.Response {
	body, err := json.Marshal(map[string]string{
		"code":    agent.CodeUnavailable,
		"message": "the basalt engine is restarting onto the upgraded binary and did not run this request; nothing was run: try again in a few seconds",
	})
	if err != nil {
		panic(err) // a map of strings
	}
	return vault.Response{Status: http.StatusServiceUnavailable, ContentType: "application/json", Body: body}
}
