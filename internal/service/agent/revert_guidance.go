package agent

import (
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

func scopeText(scope string, id fmt.Stringer) string {
	return fmt.Sprintf("%s %s", strings.ToLower(scope), id)
}

// previewGuidance is what preview_revert adds to a page of lines
// (CONTRACT.md, Next steps, PREVIEW and PREVIEW_TASK): the person decides,
// and the agent requests the revert of its own change, run or task lines.
// For a task the message always points to widening on the signing page.
func (s *Service) previewGuidance(p RevertPreview) (string, []toolresult.NextStep, error) {
	what := scopeText(string(p.Scope.Kind), p.Scope.ID)
	effect := fmt.Sprintf("would restore %d rows and leave %d as they are (changed after the agent)", p.Rows, p.Skipped)
	pointer := ""
	if p.Scope.Kind == revert.ScopeTask {
		what, pointer = "this agent's changes in "+what, " "+taskWidenPointer
	}
	if filters := filterText(p.Scope); filters != "" {
		what += filters
	}
	steps, err := guidance.NewSteps().
		AskPerson("Show the person what the revert would do and ask whether to go on, and why they want it.").
		ReviseCall(guidance.ToolRequestRevert, scopeArgs(p.Scope),
			"On yes, call request_revert with these arguments and the person's reason as intent.").
		Build()
	return fmt.Sprintf("Reverting %s %s. Say yes and the agent asks you to review the rows and sign with your passkey.%s",
		what, effect, pointer), steps, err
}

// planGuidance is what revert_plan adds to a page of a large plan's lines,
// by the plan's state (CONTRACT.md, Next steps): signing first, then the
// agent applies the pending lines in batches.
func (s *Service) planGuidance(plan RevertPlan) (string, []toolresult.NextStep, error) {
	r := plan.Revert
	b := guidance.NewSteps()
	switch {
	case r.Status == revertPending && r.Widened:
		// No link to give (RS-5): the step names the page, without a URL,
		// which the step builder requires.
		steps := []toolresult.NextStep{
			guidance.OpenLink("", "Sign the plan once with your passkey on the page where you changed the scope."),
			guidance.PersonStep(toolresult.ActionTellAgent, "Tell the agent when you have signed."),
			guidance.AgentStep(toolresult.ActionEndTurn, "End your turn: apply the lines only after the person says they signed."),
		}
		return fmt.Sprintf("%s waits for your passkey on the page where you changed the scope, until %s.",
			guidance.Sentence(revertTitle(r)), r.ExpiresAt.UTC().Format(guidance.PersonTime)), steps, nil
	case r.Status == revertPending && plan.tooLarge:
		steps, err := revertTooLargeSteps(r.ID, false)
		return plan.PersonMessage, steps, err
	case r.Status == revertPending:
		b.SendRequest(plan.RequestFile).
			OpenLink(plan.RevertURL, "Open the link, review the plan and sign it once with your passkey.").
			TellAgent("Tell the agent when you have signed.").
			EndTurn("End your turn: apply the lines only after the person says they signed.")
		steps, err := b.Build()
		return plan.PersonMessage, steps, err
	case r.Status == revertApplying:
		steps, err := s.applyBatchSteps(plan)
		return "", steps, err
	case r.Status == revertApplied:
		steps, err := b.Stop("The revert is done; do not request it again.").Build()
		return outcomeMessage(r), steps, err
	case r.Status == revertRejected:
		steps, err := b.Stop("The person rejected the revert and nothing was reverted. Do not request it again on your own.").Build()
		return rejectedMessage(r), steps, err
	}
	steps, err := b.AskPerson("Tell the person the revert expired and ask whether to prepare it again.").
		ReviseCall(guidance.ToolRequestRevert, scopeArgs(proposalOf(r)), requestAgainText).Build()
	return outcomeMessage(r), steps, err
}

// applyBatchSteps tells the agent to apply the pending lines this page
// shows (at most one batch); a page without any is read again with only the
// pending lines.
func (s *Service) applyBatchSteps(plan RevertPlan) ([]toolresult.NextStep, error) {
	id := plan.Revert.ID.String()
	lines := make([]int, 0, revert.MaxBatch)
	for _, l := range plan.Page.Items {
		if l.Outcome == guardmodel.OutcomePending && len(lines) < revert.MaxBatch {
			lines = append(lines, l.No)
		}
	}
	if len(lines) == 0 {
		return applyingSteps(plan.Revert.ID), nil
	}
	return guidance.NewSteps().CallTool(guidance.ToolApplyRevertBatch, map[string]any{guidance.ArgRevertID: id, "lines": lines},
		"Apply these pending lines, in this order; then call revert_plan again for the next ones.").Build()
}

// batchGuidance is what apply_revert_batch adds to a batch's result: more
// lines to read, or the plan's end.
func (s *Service) batchGuidance(res action.BatchResult) (string, []toolresult.NextStep, error) {
	if res.Status != revertApplied {
		return "", applyingSteps(res.RevertID), nil
	}
	steps, err := guidance.NewSteps().Stop("The revert is done; do not apply more lines.").Build()
	return fmt.Sprintf("Reverted: %d rows restored, %d left as they are because someone changed them after the agent (people win).",
		res.Restored, res.Skipped), steps, err
}

// outcomeMessage is the line for the person when a revert ended: applied, or
// expired before it was signed or finished.
func outcomeMessage(r action.Revert) string {
	restored, skipped := r.Rows, r.Skipped
	if r.Batched {
		restored, skipped = r.Progress.Restored, r.Progress.Skipped
	}
	what := guidance.Sentence(revertTitle(r))
	switch {
	case r.Status == revertApplied:
		return fmt.Sprintf("Reverted: %d rows restored, %d left as they are because someone changed them after the agent (people win).",
			restored, skipped)
	case r.SignedAt != nil:
		return fmt.Sprintf("%s was signed but not finished by %s: %d rows restored, %d left as they are, %d not restored.",
			what, applyByText(r), restored, skipped, r.Progress.Pending)
	}
	return fmt.Sprintf("%s expired at %s without your signature; nothing was reverted.", what, r.ExpiresAt.UTC().Format(guidance.PersonTime))
}
