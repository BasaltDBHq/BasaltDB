package agent

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// LinkNotFound is the pages' answer for a link no agent knows: incomplete,
// expired or replaced by a newer one. It is the same whichever of those it
// is (CONTRACT.md, Link secrets), and the person's next step is to ask the
// agent for a new link.
func LinkNotFound() *mcp.ToolError {
	steps, err := NewSteps().TellAgent("Ask the agent for the link again.").Build()
	if err != nil {
		panic(err) // a fixed step: a failure is a build defect
	}
	return &mcp.ToolError{
		Code: CodeNotFound, Reason: reasonLink,
		Message: "no held write or revert with this id, or the link is incomplete or was replaced by a newer one: " +
			"ask the agent for the link again",
		PersonMessage: "This link is incomplete, expired or was replaced by a newer one. Ask the agent for the link again.",
		NextSteps:     steps,
	}
}

// PageFailure is err as the pages answer it: the contract's error body with
// the person's message and the steps the catalog gives it. The page shows
// them to the person, so the caller keeps only the PERSON steps.
func (s *Service) PageFailure(err error) *mcp.ToolError {
	te := ToolError(err)
	if s.pageSignatureFailure(te) {
		return te
	}
	return s.Failure("", nil, te)
}

// pageSignatureFailure gives a refused signature the guidance for the page
// the person is already on: sign again there, so no link is named (the
// engine knows no short link's secret to build one). It reports whether te
// was such a refusal.
func (s *Service) pageSignatureFailure(te *mcp.ToolError) bool {
	var what, again string
	switch te.Code {
	case CodeApprovalInvalid:
		what, again = "approval", "Approve again on this page."
	case string(guard.CodeRevertInvalid):
		what, again = "revert", "Sign again on this page."
	default:
		return false
	}
	switch te.Reason {
	case reasonBadSignature:
		te.PersonMessage = fmt.Sprintf("The %s code did not verify, so nothing was applied. %s", what, again)
		return true
	case reasonPasskeyRevoked:
		steps, err := NewSteps().
			RunCommand(s.Commands.PasskeyList(), "See which passkeys this database accepts.").
			RunCommand(s.Commands.Init("--add-passkey"), "Register your passkey with this command: it adds the one you use and changes nothing else.").
			Build()
		if err != nil {
			s.Log.Error("cannot build the page's passkey steps", "err", err)
			return false
		}
		te.NextSteps = steps
		te.PersonMessage = fmt.Sprintf("The %s was signed with a passkey this database does not accept (unknown or revoked), "+
			"so nothing was applied. Check your passkeys, register one if needed, then try again on this page.", what)
		return true
	}
	return false
}
