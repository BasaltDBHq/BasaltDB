package agent

import (
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// A held write keeps its preview lines whole, up to guardmodel.MaxHeldLinesBytes
// of text in all (basalt_meta version 37; CONTRACT.md, Large values). Over
// it the write cannot be held: STATEMENT_REFUSED HOLD_TOO_LARGE, never
// INTERNAL. The guard refuses it itself (BS007, detail HOLD_TOO_LARGE),
// and the engine checks the same cap, so an older guard, whose
// preview_lines has no cap and whose hold_action refuses any line over
// 64 KiB as invalid input (BS008), gets the same answer.

// olderGuardNote marks the HOLD_TOO_LARGE message of a guard before
// version 37: upgrading the guard is what lets the write be held.
const olderGuardNote = "this database's guard holds a line of at most 64 KiB"

// holdTooLarge is STATEMENT_REFUSED HOLD_TOO_LARGE for preview lines a
// hold cannot keep, or nil when they fit. holdErr is hold_action's error
// (nil before the hold): BS008 with a line over 64 KiB is an older
// guard's per-line cap.
func holdTooLarge(lines []string, holdErr error) *toolresult.ToolError {
	var total, longest int
	for _, l := range lines {
		total += len(l)
		longest = max(longest, len(l))
	}
	if total > guardmodel.MaxHeldLinesBytes {
		return &toolresult.ToolError{Code: CodeStatementRefused, Reason: action.ReasonHoldTooLarge, Message: fmt.Sprintf(
			"the write's preview lines are %s; a held write holds at most %s of them, so it cannot be held for approval",
			largevalue.SizeText(int64(total)), largevalue.SizeText(guardmodel.MaxHeldLinesBytes))}
	}
	if code, ok := ledgerCode(holdErr); ok && longest > guardmodel.MaxHeldLineBytesBefore37 && code == guardmodel.CodeLedgerInputInvalid {
		return &toolresult.ToolError{Code: CodeStatementRefused, Reason: action.ReasonHoldTooLarge, Message: fmt.Sprintf(
			"a preview line of the write is %s, and %s (basalt_meta before version 37): upgrading the guard lets it hold the write",
			largevalue.SizeText(int64(longest)), olderGuardNote)}
	}
	return nil
}

// holdTooLargeSteps: the agent stops and asks. The person makes the change
// themselves or has the agent write fewer rows per call, each still held;
// on an older guard, an upgrade lets the same write be held.
func (s *Service) holdTooLargeSteps(b *guidance.Steps, te *toolresult.ToolError) string {
	b.Stop("Do not retry the write as it is.")
	if strings.Contains(te.Message, olderGuardNote) {
		b.AskPerson("Tell the person this database's guard is too old to hold a write with rows this large and needs an upgrade; " +
			"send the write again once they say they upgraded it.")
		return "The agent's write is too large to hold for your approval on this database's guard, which holds rows of at most 64 KiB. " +
			"To hold it, update the guard: the agent gives you a link. Then tell the agent."
	}
	b.AskPerson("Tell the person the write is too large to hold for their approval, and ask whether they make the change themselves " +
		"or want you to change fewer rows per write, each held for their approval.")
	return fmt.Sprintf("The agent's write is too large to hold for your approval: a held write's rows come to at most %s. "+
		"Make the change yourself if you want it, or ask the agent to change fewer rows per write.", largevalue.SizeText(guardmodel.MaxHeldLinesBytes))
}
