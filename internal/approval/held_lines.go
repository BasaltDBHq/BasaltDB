package approval

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// A held write keeps its preview lines whole, up to guardmodel.MaxHeldLinesBytes
// of text in all (CONTRACT.md, Large values). Over it the write cannot be
// held: STATEMENT_REFUSED HOLD_TOO_LARGE, never INTERNAL. The service
// checks the cap on the lines before the hold; the store may refuse them
// too, which reaches the agent as the same answer.

// HoldTooLarge is STATEMENT_REFUSED HOLD_TOO_LARGE for preview lines a
// hold cannot keep, or nil when they fit.
func HoldTooLarge(lines []string) *toolresult.ToolError {
	var total int
	for _, l := range lines {
		total += len(l)
	}
	if total > guardmodel.MaxHeldLinesBytes {
		return &toolresult.ToolError{Code: guidance.CodeStatementRefused, Reason: action.ReasonHoldTooLarge, Message: fmt.Sprintf(
			"the write's preview lines are %s; a held write holds at most %s of them, so it cannot be held for approval",
			largevalue.SizeText(int64(total)), largevalue.SizeText(guardmodel.MaxHeldLinesBytes))}
	}
	return nil
}

// HoldTooLargeSteps: the agent stops and asks. The person makes the change
// themselves or has the agent write fewer rows per call, each still held.
func (ac *Service) HoldTooLargeSteps(b *guidance.Steps, _ *toolresult.ToolError) string {
	b.Stop("Do not retry the write as it is.")
	b.AskPerson("Tell the person the write is too large to hold for their approval, and ask whether they make the change themselves " +
		"or want you to change fewer rows per write, each held for their approval.")
	return fmt.Sprintf("The agent's write is too large to hold for your approval: a held write's rows come to at most %s. "+
		"Make the change yourself if you want it, or ask the agent to change fewer rows per write.", largevalue.SizeText(guardmodel.MaxHeldLinesBytes))
}
