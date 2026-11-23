package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// RevealApproval reveals the hidden rows of one of this agent's held
// writes to the person on the approval page: open_reveal checks the proof
// and gives a ticket, then the held write re-runs in a preview that rolls
// back, recorded as an apply records it, and reveal_approval_rows reads
// the rows there, for the page holding secret, the approval's live link
// secret. The ticket lives in this call only.
func (ac *approvalCase) RevealApproval(ctx context.Context, id uuid.UUID, secret string, in linksvc.RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.RevealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	a, err := ac.openApproval(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	held, err := heldWrite(a, ac.writes)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	ticket, err := ac.deps.Store.OpenReveal(ctx, id, in.Proof.Assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, ac.revealApprovalError(err, ac.delivery.PageLink(links.Approval, id, secret))
	}
	defer clear(ticket)
	rows, err := ac.deps.Store.RevealPreview(ctx, held.intent, held.op, held.sql, held.params, id, ticket)
	if err != nil {
		return approval.RevealAnswer{}, ac.revealApprovalError(err, ac.delivery.PageLink(links.Approval, id, secret))
	}
	return linksvc.CheckedAnswer(a.Lines, rows)
}

// heldRun is what re-runs a held write: its statement and parameters as
// the binding carries them, under the run, task and intent it was held in.
type heldRun struct {
	intent action.Intent
	op     action.Op
	sql    string
	params []any
}

// heldWrite reads the held write from approval a's binding: the statement,
// its parameters (numbers kept exact, as the write tool decodes them), and
// the run it belongs to.
func heldWrite(a action.Approval, check statementChecker) (heldRun, error) {
	b, err := approval.ParseBinding(a.BindingText)
	if err != nil {
		return heldRun{}, err
	}
	stmt, err := check.Check(b.Statement, action.ToolWrite)
	if err != nil {
		return heldRun{}, fmt.Errorf("the held statement no longer parses: %w", err)
	}
	params := make([]any, 0, len(b.Params))
	for _, raw := range b.Params {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return heldRun{}, fmt.Errorf("a held parameter: %w", err)
		}
		params = append(params, v)
	}
	in := action.Intent{RunID: b.RunID, Text: b.Intent}
	if b.TaskID != nil {
		in.TaskID = *b.TaskID
	}
	return heldRun{intent: in, op: stmt.Op, sql: b.Statement, params: params}, nil
}

// revealApprovalError is the page's answer to a reveal Postgres refused.
func (ac *approvalCase) revealApprovalError(err error, link string) error {
	code, _ := guidance.LedgerCode(err)
	detail := guidance.StoreDetail(err)
	switch {
	case code == guardmodel.CodeApprovalInvalid && detail == guardmodel.RevealRefused:
		return linksvc.RevealRefused(guidance.CodeApprovalInvalid, link)
	case code == guardmodel.CodeApprovalInvalid && detail == guardmodel.RevealRowsChanged:
		return linksvc.RevealRowsChanged(guidance.CodeApprovalInvalid, "approval", "This approval can no longer apply; ask the agent to try the write again")
	case code == guardmodel.CodeApprovalInvalid && detail == approvalNotFoundDetail:
		return linksvc.ErrNotThisAgent
	case code == guardmodel.CodeApprovalInvalid:
		return &guidance.PageError{ToolError: &toolresult.ToolError{
			Code:          guidance.CodeApprovalInvalid,
			Message:       "the hidden rows cannot be shown: the approval was signed or used meanwhile",
			PersonMessage: "This approval was signed or used meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}

// approvalNotFoundDetail is the guard's detail for an approval the calling
// role does not hold, or none.
const approvalNotFoundDetail = "no such approval"
