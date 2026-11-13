package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// approvalPoll is how often basalt approve checks whether the page's relay
// signed the approval.
const approvalPoll = revertPoll

// awaitApproval waits for a held write to be signed on the engine's local
// page, which relays the signature, while still taking a pasted code
// (CONTRACT.md, CLI). It ends when the approval is signed or applied, or
// expires, like awaitRevert.
func awaitApproval(c *cliIO, l *agentLedger, id uuid.UUID) int {
	fmt.Fprintln(c.stderr, "basalt: waiting for your signature on the approval page (or paste the code it shows here)...")
	// A closed stdin just leaves the page to finish it. The paste is read
	// as the other prompts read it (CONTRACT.md, CLI, Pasted codes), so a
	// code over a terminal line's limit does not stall; stopPaste waits for
	// the read to restore the terminal's modes.
	pastes, stopPaste := c.pasteInBackground(c.ctx)
	defer stopPaste()
	tick := time.NewTicker(approvalPoll)
	defer tick.Stop()
	for {
		select {
		case p := <-pastes:
			if p.err == nil {
				stopPaste()
				return submitApproval(c, l, p.code)
			}
			reportPasteError(c, p.err, "waiting for the approval page")
			pastes = nil // only the page can finish it now
			continue
		case <-c.ctx.Done():
			return c.fail(c.ctx.Err())
		case <-tick.C:
		}
		a, err := l.FindApproval(c.ctx, id)
		if errors.Is(err, ledger.ErrApprovalNotFound) {
			return c.fail(fmt.Errorf("approval %s is not a held write of this agent", id))
		}
		if err != nil {
			return c.fail(err)
		}
		switch {
		case a.Status == ledger.ApprovalExpired || (a.Status == ledger.ApprovalPending && !c.now().Before(a.ExpiresAt)):
			return c.fail(fmt.Errorf("approval %s expired unsigned; nothing was applied. Ask the agent to repeat the write for a new approval", id))
		case a.Status == ledger.ApprovalPending:
			continue
		case a.Status == ledger.ApprovalApplied:
			fmt.Fprintf(c.stderr, "basalt: approval %s is already applied\n", id)
			return exitOK
		}
		return approvalSigned(c, id)
	}
}
