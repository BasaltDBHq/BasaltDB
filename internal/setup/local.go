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
	// link, for the page's Remove: as long as an approval wait.
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
)

// ServiceDialog is one fixed script run through the administrator dialog,
// with what init says around it.
type ServiceDialog struct {
	Script                                            func(goos string) (string, error)
	Prompt, NoDialog, Asking, Cancelled, Failed, Done string
}
