package setup

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// SetupWait bounds how long init waits for the engine's setup page after
// the service starts.
const (
	SetupWait     = 30 * time.Second
	SetupWaitStep = 250 * time.Millisecond
	// RemovalWait is how long init waits, after it opened the Update/Remove
	// link, for the page's Remove: as long as an approval wait. The page's
	// Update ends it sooner.
	RemovalWait     = guidance.DefaultApprovalWait
	RemovalWaitStep = 500 * time.Millisecond
)

// BasaltEngineState is what the engine's setup routes say about it.
type BasaltEngineState int

const (
	EngineWaiting    BasaltEngineState = iota // no config yet: the setup page installs
	EngineSetUp                               // it has a config
	EngineRemoved                             // the page removed its last agent
	EngineResetAsked                          // the person said the database is not theirs
	EngineUpdated                             // the page's Update for the agent finished
)
