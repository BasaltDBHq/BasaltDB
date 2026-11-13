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
	codes := make(chan string, 1)
	go func() {
		// A closed or empty stdin just leaves the page to finish it.
		if code, err := c.line(); err == nil && code != "" {
			codes <- code
		}
	}()
	tick := time.NewTicker(approvalPoll)
	defer tick.Stop()
	for {
		select {
		case code := <-codes:
			return submitApproval(c, l, code)
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
