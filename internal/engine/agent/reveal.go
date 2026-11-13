package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// The pages' reveal routes (CONTRACT.md, Approvals, Rows hidden from the
// agent; Local pages, POST …/reveal): the person proves with their passkey
// that they want to see the values of the lines the agent role cannot
// read, and Postgres returns them for this one answer. The engine keeps
// nothing: the reveal key, the ticket and the rows live for one request,
// are never logged, and never reach the MCP channel.

// RevealRequest is the body of POST …/reveal (reveal-request.schema.json):
// the person's proof and the reveal secret the page made for it.
type RevealRequest struct {
	Proof        ScopeProof `json:"proof"`
	RevealSecret string     `json:"revealSecret"`
}

// revealKey is the key Postgres checks the proof against, derived from the
// page's reveal secret, which never reaches Postgres.
func (in RevealRequest) revealKey() ([]byte, error) {
	raw, err := links.DecodeSecret(in.RevealSecret)
	if err != nil {
		return nil, &ArgumentError{Message: "revealSecret must be 16 random bytes, base64url without padding"}
	}
	defer clear(raw)
	return approval.RevealKey(raw)
}

// RevealApproval reveals the hidden rows of one of this agent's held
// writes to the person on the approval page: open_reveal checks the proof
// and gives a ticket, then the held write re-runs in a preview that rolls
// back, recorded as an apply records it, and reveal_approval_rows reads
// the rows there. The ticket lives in this call only.
func (s *Service) RevealApproval(ctx context.Context, id uuid.UUID, in RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.revealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	a, err := s.openApproval(ctx, id, nil)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	held, err := heldWrite(a)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	ticket, err := s.Approvals.OpenReveal(ctx, id, in.Proof.assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, s.revealApprovalError(err)
	}
	defer clear(ticket)
	rows, err := s.Approvals.RevealPreview(ctx, held.intent, held.op, held.sql, held.params, id, ticket)
	if err != nil {
		return approval.RevealAnswer{}, s.revealApprovalError(err)
	}
	return checkedAnswer(a.Lines, rows)
}

// RevealRevert reveals the hidden rows of a revert this agent's role
// prepared to the person on the revert page holding secret, its live link
// secret. It serializes with the revert's other page routes; Postgres
// locks the revert row, so a signature racing it comes first or second,
// never between.
func (s *Service) RevealRevert(ctx context.Context, id uuid.UUID, secret string, in RevealRequest) (approval.RevealAnswer, error) {
	key, err := in.revealKey()
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer clear(key)
	release, err := s.rescopes.lock(ctx, id)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	defer release()
	r, err := s.openRevert(ctx, id, nil)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	st, held, err := s.heldState(r, secret)
	if err != nil {
		return approval.RevealAnswer{}, err
	}
	lines := r.Lines
	if r.Widened {
		if !held {
			nonce, err := s.Reverts.RevertNonce(ctx, id)
			if err != nil {
				return approval.RevealAnswer{}, err
			}
			return approval.RevealAnswer{}, widenAgain(nonce)
		}
		lines = st.request.Lines
	}
	out, err := s.Reverts.RevealRevertRows(ctx, id, in.Proof.assertion(), key)
	if err != nil {
		return approval.RevealAnswer{}, s.revealRevertError(r, err)
	}
	if out.RowsChanged {
		return approval.RevealAnswer{}, revealRowsChanged(CodeRevertInvalid, "revert", "Prepare it again")
	}
	return checkedAnswer(lines, out.Rows)
}

// checkedAnswer is the answer the page gets, checked first as the page
// checks it: rows of redacted lines, in order, each hashing to its line
// (or with its SECRET columns null). A row that fails is a defect, never
// shown.
func checkedAnswer(lines []string, rows []approval.RevealedRow) (approval.RevealAnswer, error) {
	if rows == nil {
		rows = []approval.RevealedRow{}
	}
	answer := approval.RevealAnswer{Rows: rows}
	if _, err := approval.CheckRevealAnswer(lines, answer); err != nil {
		return approval.RevealAnswer{}, fmt.Errorf("the guard's reveal answer does not match the request: %w", err)
	}
	return answer, nil
}

// heldRun is what re-runs a held write: its statement and parameters as
// the binding carries them, under the run, task and intent it was held in.
type heldRun struct {
	intent guard.Intent
	op     sqlguard.Op
	sql    string
	params []any
}

// heldWrite reads the held write from approval a's binding: the statement,
// its parameters (numbers kept exact, as the write tool decodes them), and
// the run it belongs to.
func heldWrite(a ledger.Approval) (heldRun, error) {
	b, err := approval.ParseBinding(a.BindingText)
	if err != nil {
		return heldRun{}, err
	}
	stmt, err := sqlguard.Check(b.Statement, sqlguard.ToolWrite)
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
	in := guard.Intent{RunID: b.RunID, Text: b.Intent}
	if b.TaskID != nil {
		in.TaskID = *b.TaskID
	}
	return heldRun{intent: in, op: stmt.Op, sql: b.Statement, params: params}, nil
}

// revealApprovalError is the page's answer to a reveal Postgres refused.
func (s *Service) revealApprovalError(err error) error {
	code, _ := guard.CodeOf(err)
	detail := guardDetail(err)
	switch {
	case code == guard.CodeApprovalInvalid && detail == guard.RevealRefused:
		return revealRefused(CodeApprovalInvalid)
	case code == guard.CodeApprovalInvalid && detail == guard.RevealRowsChanged:
		return revealRowsChanged(CodeApprovalInvalid, "approval", "This approval can no longer apply; ask the agent to try the write again")
	case code == guard.CodeApprovalInvalid && detail == approvalNotFoundDetail:
		return ErrNotThisAgent
	case code == guard.CodeApprovalInvalid:
		return &PageError{ToolError: &mcp.ToolError{
			Code:          CodeApprovalInvalid,
			Message:       "the hidden rows cannot be shown: the approval was signed or used meanwhile",
			PersonMessage: "This approval was signed or used meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}

// revealRevertError is the page's answer to a revert reveal Postgres
// refused.
func (s *Service) revealRevertError(r ledger.Revert, err error) error {
	code, _ := guard.CodeOf(err)
	detail := guardDetail(err)
	switch {
	case code == guard.CodeRevertInvalid && detail == guard.RevealRefused:
		return revealRefused(CodeRevertInvalid)
	case code == guard.CodeRevertInvalid && detail == revertNotFoundDetail:
		return ErrNotThisAgent
	case code == guard.CodeRevertExpired:
		return s.revertExpired(r)
	case code == guard.CodeRevertInvalid:
		return &PageError{ToolError: &mcp.ToolError{
			Code:          CodeRevertInvalid,
			Message:       "the hidden rows cannot be shown: the revert was signed or rejected meanwhile",
			PersonMessage: "This revert was signed or rejected meanwhile, so its hidden rows can no longer be shown.",
		}}
	}
	return err
}

// approvalNotFoundDetail is the guard's detail for an approval the calling
// role does not hold, or none.
const approvalNotFoundDetail = "no such approval"

func guardDetail(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Detail
	}
	return ""
}

// revealRefused is every refused proof, key, nonce or ticket: one answer,
// so the agent holding the link learns nothing from which check failed.
func revealRefused(code string) error {
	return &PageError{ToolError: &mcp.ToolError{
		Code: code, Reason: guard.RevealRefused,
		Message: "showing the hidden rows was refused: it needs the person's passkey on this page; nothing was shown",
		PersonMessage: "Basalt could not check your passkey for showing the hidden values, so nothing was shown. " +
			"Press Show values again; your approval or revert is not affected.",
	}}
}

// revealRowsChanged is a reveal whose hidden rows changed since the agent
// asked: nothing is shown, and the item can no longer apply as signed.
func revealRowsChanged(code, what, then string) error {
	return &PageError{ToolError: &mcp.ToolError{
		Code: code, Reason: reasonRowsChanged,
		Message:       fmt.Sprintf("the hidden rows of this %s changed since it was prepared; nothing was shown", what),
		PersonMessage: "These rows changed since the agent asked. " + then + ".",
	}}
}
