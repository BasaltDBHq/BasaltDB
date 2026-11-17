package action

import "github.com/google/uuid"

// Intent is what an action is for: the agent's run, its task, and the
// intent the agent stated.
type Intent struct {
	RunID  uuid.UUID
	TaskID uuid.UUID // uuid.Nil when the run has no task
	Text   string
}
