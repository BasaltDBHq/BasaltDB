package ledger

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// History is one page of a run's change records with the rows each wrote.
type History = action.History[action.Change, action.RowChange]

// runFinder is the ledger lookup of one run of the agent.
type runFinder interface {
	FindRun(ctx context.Context, id uuid.UUID) (action.Run, error)
}

// historyStore is what the history read takes from the agent's store.
type historyStore interface {
	runFinder
	History(ctx context.Context, p action.ChangeListParams) (History, error)
}

// Reads is the ledger's read side: what the agent's runs recorded.
type Reads struct {
	store historyStore
}

// NewReads returns the ledger reads over the agent's store.
func NewReads(store historyStore) *Reads {
	return &Reads{store: store}
}

// History returns one page of a run's change records.
func (r *Reads) History(ctx context.Context, p action.ChangeListParams) (History, error) {
	if _, err := FindRun(ctx, r.store, p.RunID); err != nil {
		return History{}, err
	}
	return r.store.History(ctx, p)
}

// FindRun looks up the agent's run in its ledger: the zero run for uuid.Nil, or
// NOT_FOUND. Every domain that takes a runId goes through it.
func FindRun(ctx context.Context, store runFinder, id uuid.UUID) (action.Run, error) {
	if id == uuid.Nil {
		return action.Run{}, nil
	}
	run, err := store.FindRun(ctx, id)
	if errors.Is(err, action.ErrRunNotFound) {
		return action.Run{}, &toolresult.ToolError{Code: guidance.CodeNotFound, Reason: guidance.ReasonRun, Message: fmt.Sprintf("run %s is not one of this agent's runs; start one with run_start", id)}
	}
	return run, err
}
