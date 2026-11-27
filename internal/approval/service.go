package approval

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Service is the held writes use case: what is held for the person, the
// links that open it, the pending list and the reveal. It holds a reference to
// the shared core group and to its own Deps, and a copy of the store set it
// reads the store through. What it needs from the other use cases it names as
// small ports of its own: the delivery of links and notices, the open
// reverts, the run check, and the call admission.
type Service struct {
	core     Core
	store    StoreSet
	deps     *Deps
	delivery Delivery
	reverts  Reverts
	runs     RunChecker
	admit    Admitter
}

// New builds the approval use case over core and the approval's store set,
// with the other use cases it asks: the delivery of links and notices and the
// open reverts. It panics on a set with a nil port, since the service reads
// the store only through them.
func New(core Core, store StoreSet, deps *Deps, delivery Delivery, reverts Reverts, runs RunChecker, admit Admitter) *Service {
	if missing := store.missingPorts(); len(missing) > 0 {
		panic("approval: store set missing ports: " + strings.Join(missing, ", "))
	}
	return &Service{core: core, store: store, deps: deps, delivery: delivery, reverts: reverts, runs: runs, admit: admit}
}

// FindApproval reads one held write of the agent's, for the write use case.
func (ac *Service) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	return ac.store.Records.FindApproval(ctx, id)
}

// HeldWrite is a write held for the person's approval, with the request it
// is held as and the preview lines its notice is built from.
type HeldWrite struct {
	approvalstore.Held
	Request action.Request
	Lines   []string
}

// HoldRefusalError is a write the hold refused, which the agent records as a
// refused write: a write that cannot be run again the same way, an error of
// its preview run, or preview lines over the cap. Err is the answer.
type HoldRefusalError struct {
	Err error
}

func (e *HoldRefusalError) Error() string { return e.Err.Error() }

func (e *HoldRefusalError) Unwrap() error { return e.Err }

// Hold holds a write for the person's approval (the write use case's one
// call): the store previews it, Basalt checks the lines (some rows, within
// the cap), and the store holds it with op, the request the preview returns
// (the agent's, with any value that changes between runs fixed by the
// store) and the preview's bound fields and lines. The request is passed on
// unread. A refusal the agent records comes as a *HoldRefusalError; any other
// error, the agent answers without recording it.
func (ac *Service) Hold(ctx context.Context, in action.Intent, req action.Request, op action.Op) (HeldWrite, error) {
	p, err := ac.store.Holds.Preview(ctx, in, req)
	var notRepeatable *action.RefusalError
	var previewFailed *approvalstore.PreviewFailedError
	switch {
	case errors.As(err, &previewFailed):
		return HeldWrite{}, &HoldRefusalError{Err: previewFailed.Err}
	case errors.As(err, &notRepeatable):
		return HeldWrite{}, &HoldRefusalError{Err: err}
	case err != nil:
		return HeldWrite{}, err
	}
	if len(p.Lines) == 0 {
		// The rows went away between the attempt and the preview.
		return HeldWrite{}, &toolresult.ToolError{Code: guidance.CodeStoreError, Reason: guidance.ReasonNoRowsNow, Message: "the write changes no rows now; read again and decide"}
	}
	if te := HoldTooLarge(p.Lines); te != nil {
		return HeldWrite{}, &HoldRefusalError{Err: te}
	}
	held, err := ac.store.Holds.Hold(ctx, in, approvalstore.HoldRequest{Op: op, Request: p.Request, Assigned: p.Assigned, Lines: p.Lines})
	if err != nil {
		return HeldWrite{}, err
	}
	return HeldWrite{Held: held, Request: p.Request, Lines: p.Lines}, nil
}
