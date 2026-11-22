package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// cliPages runs a guard command with the host h, stdin, and a context that
// ends after limit, for a command that waits on the page.
func cliPages(t *testing.T, h host, stdin string, limit time.Duration, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	var stdout, stderr bytes.Buffer
	c := newIO(ctx, stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr}, func(string) string { return "" })
	c.host = h
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

// approvalsAt is a ledger whose FindApproval answers the given approvals in
// turn, then the last one again.
type approvalsAt struct {
	person.Ledger
	seq []ledger.Approval
	n   int
}

func (a *approvalsAt) FindApproval(context.Context, uuid.UUID) (ledger.Approval, error) {
	got := a.seq[min(a.n, len(a.seq)-1)]
	a.n++
	return got, nil
}

// heldWrite is a write held for approval, with the agent's credential file
// and the approval id.
func heldWrite(t *testing.T) (string, string) {
	t.Helper()
	d, _, cred := revertSetup(t)
	_ = d
	return cred, holdDelete(t, cred).ApprovalID.String()
}

func TestApproveOpenIssuesAShortLinkWithoutReissue(t *testing.T) {
	t.Parallel()
	cred, id := heldWrite(t)
	h := newFakeHost(t)
	h.pagesUp = true
	r := cliPages(t, h, "", 2*time.Second, "approve", "--agent", "bot", "--config", localConfig(t, cred), "--open", id)
	require.Len(t, h.issued, 1)
	require.Equal(t, []string{testPagesOrigin + "/approvals/" + id + "#s=" + fakeSecret}, h.opened)
	require.Contains(t, r.stderr, "waiting for your signature on the approval page")
	require.NotContains(t, r.stderr, "basalt approve '<code>'")
}

func TestAwaitApprovalEnds(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name string
		seq  []ledger.Approval
		code int
		line string
	}{
		{
			"signed",
			[]ledger.Approval{{Status: ledger.ApprovalPending, ExpiresAt: future}, {Status: ledger.ApprovalApproved}},
			exitOK, "approval " + id.String() + " signed; the agent applies it by repeating the write",
		},
		{
			"already applied",
			[]ledger.Approval{{Status: ledger.ApprovalApplied}},
			exitOK, "approval " + id.String() + " is already applied",
		},
		{
			"expired",
			[]ledger.Approval{{Status: ledger.ApprovalExpired}},
			exitError, "expired unsigned",
		},
		{
			"pending past its deadline",
			[]ledger.Approval{{Status: ledger.ApprovalPending, ExpiresAt: time.Now().Add(-time.Minute)}},
			exitError, "expired",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c := newIO(ctx, stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(string) string { return "" })
			l := &agentLedger{Ledger: &approvalsAt{seq: tc.seq}}
			require.Equal(t, tc.code, awaitApproval(c, l, id), stderr.String())
			require.Contains(t, stderr.String(), tc.line)
		})
	}
}

func TestAwaitApprovalTakesAPastedCode(t *testing.T) {
	t.Parallel()
	d, person, cred := revertSetup(t)
	held := holdDelete(t, cred)
	id := held.ApprovalID.String()
	as, err := person.Sign(approval.Challenge(bindingOf(t, cred, held.ApprovalID)), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := approval.NewResponse(held.ApprovalID, as).Code()
	require.NoError(t, err)

	h := newFakeHost(t)
	h.pagesUp = true
	r := cliPages(t, h, code+"\n", 30*time.Second, "approve", "--agent", "bot", "--config", localConfig(t, cred), "--open", id)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "approval "+id+" signed")
	require.Equal(t, 1, count(t, d, `SELECT count(approval_id)::int FROM basalt_meta.approvals WHERE approved_at IS NOT NULL`))
}

func TestApproveOpenWithoutLocalPagesStillAsksForTheCode(t *testing.T) {
	t.Parallel()
	cred, id := heldWrite(t)
	h := newFakeHost(t)
	r := cliPages(t, h, "", 10*time.Second, "approve", "--agent", "bot", "--config", localConfig(t, cred), "--open", id)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, h.issued)
	require.Len(t, h.opened, 1)
	require.Contains(t, h.opened[0], "/approvals/"+id+"#2.")
	require.Contains(t, r.stderr, "basalt approve '<code>'")
}

func TestApproveShowWithLocalPagesWaits(t *testing.T) {
	t.Parallel()
	cred, id := heldWrite(t)
	h := newFakeHost(t)
	h.pagesUp = true
	r := cliPages(t, h, "", 2*time.Second, "approve", "--agent", "bot", "--config", localConfig(t, cred), "--show", id)
	require.Equal(t, testPagesOrigin+"/approvals/"+id+"#s="+fakeSecret+"\n", r.stdout)
	require.Contains(t, r.stderr, "this link replaces the one the agent showed you")
	require.Contains(t, r.stderr, "waiting for your signature on the approval page")
}
