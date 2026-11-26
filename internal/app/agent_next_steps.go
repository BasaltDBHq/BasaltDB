package app

import (
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// Failure maps err, raised by a call of tool with args, to the contract's
// error body (CONTRACT.md, Error codes and Next steps).
func (s *Service) Failure(tool string, args map[string]any, err error) *toolresult.ToolError {
	return s.agent.Failure(tool, args, err)
}

// UnavailableSteps builds the steps and the person's message of an
// UNAVAILABLE error, which the status use case owns.
func (s *Service) UnavailableSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	return s.status.UnavailableSteps(b, te, f)
}

// ApprovalLinkError is the APPROVAL_INVALID answer for an approval that
// needs the person back at its page, which the approval use case owns.
func (s *Service) ApprovalLinkError(te *toolresult.ToolError, n linksvc.HeldAnswer) *toolresult.ToolError {
	return s.approval.ApprovalLinkError(te, n)
}
