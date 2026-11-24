package revert

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

func TestRevertNoticeFollowsTheHandOverOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	small, big := revertOf(t, "Undo the bad merge", revertLines(2), false), revertOf(t, "Undo the bad merge", revertLines(60), false)

	short, err := newService(t, "linux", "", pagesOrigin(localPages), linkBudget(1)).revertNotice(ctx, big)
	require.NoError(t, err)
	require.Contains(t, short.URL, "#s=", "a short link is never measured")
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: short.URL}}, short.Links)
	require.Contains(t, short.Message, "\n\n"+short.URL)
	require.Nil(t, short.File)
	stepcatalogtest.RequirePersonMessage(t, short.Message, short.Links)

	within, err := newService(t, "linux", "", linkBudget(links.DefaultBudget)).revertNotice(ctx, small)
	require.NoError(t, err)
	require.Contains(t, within.URL, "#2.")
	require.LessOrEqual(t, len(within.URL), links.DefaultBudget)
	require.Nil(t, within.File)
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: within.URL}}, within.Links)
	stepcatalogtest.RequirePersonMessage(t, within.Message, within.Links)

	over, err := newService(t, "linux", "", linkBudget(links.DefaultBudget)).revertNotice(ctx, big)
	require.NoError(t, err)
	require.Greater(t, len(over.long), links.DefaultBudget, "the fixture must be over budget")
	require.Regexp(t, `/reverts/`+caseRevertID+`#h=[A-Za-z0-9_-]{22}$`, over.URL)
	require.NotNil(t, over.File)
	require.Equal(t, links.RevertFile(uuid.MustParse(caseRevertID)), over.File.FileName)
	require.Equal(t, links.RequestHash(over.File.Text), over.URL[strings.Index(over.URL, "#h=")+3:])
	require.Contains(t, over.Message, "Review only, this link cannot be signed: open this link, then open the request file the agent sends you")
	require.Contains(t, over.Message, "\n\n"+over.URL)
	require.NotContains(t, over.Message, "#2.")
	require.Equal(t, []toolresult.Link{{Label: "Review and sign the revert", URL: over.URL}}, over.Links)
	stepcatalogtest.RequirePersonMessage(t, over.Message, over.Links)
}

// TestRevertNoticeNamesOnlyTheFileWithoutBlocks: a request too long for ten
// blocks goes as a file only, and the message says so.
func TestRevertNoticeNamesOnlyTheFileWithoutBlocks(t *testing.T) {
	t.Parallel()
	huge := revertOf(t, "Undo the bad merge", revertLines(200), false)
	n, err := newService(t, "linux", "", linkBudget(links.DefaultBudget)).revertNotice(context.Background(), huge)
	require.NoError(t, err)
	require.NotNil(t, n.File)
	require.Greater(t, len(n.File.Text), links.RequestPieceChars*links.RequestMaxBlocks, "the fixture must need more than ten blocks")
	require.Nil(t, n.File.Blocks)
	require.Contains(t, n.Message, "open the request file the agent sends you:")
	require.NotContains(t, n.Message, "text blocks")
	stepcatalogtest.RequirePersonMessage(t, n.Message, n.Links)
}

func TestRevertNoticeStaysWithin500CharactersWhateverIsLong(t *testing.T) {
	t.Parallel()
	intent := strings.Repeat("Undo the bad merge of the leads. ", 15) // 495 characters, the tool's limit is 500
	for _, batched := range []bool{false, true} {
		for _, origin := range []string{localPages, ""} {
			r := revertOf(t, intent, revertLines(60), batched)
			n, err := newService(t, "linux", "", pagesOrigin(origin), linkBudget(1)).revertNotice(context.Background(), r)
			require.NoError(t, err)
			stepcatalogtest.RequirePersonMessage(t, n.Message, n.Links)
		}
	}
}

// REVERT_INVALID refusals that send the person back to the revert page
// (BAD_SIGNATURE, PASSKEY_REVOKED) follow the link budget like the request:
// with the pages served, the short link the person has (no url, never the
// long link over the budget); without them, the hash link on the step only,
// naming the request file the agent already sent, and no SEND_REQUEST.
func TestRevertInvalidRestatesTheRequestsLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	big := revertOf(t, "Undo the bad merge", revertLines(60), false)
	for _, origin := range []string{localPages, ""} {
		s := newService(t, "linux", "", pagesOrigin(origin), linkBudget(links.DefaultBudget))
		long, err := s.longRevertLink(ctx, big)
		require.NoError(t, err)
		require.Greater(t, len(long), links.DefaultBudget, "the fixture must be over budget")
		for name, refuse := range map[string]func() error{
			guidance.ReasonBadSignature:   func() error { return s.badSignature(ctx, big, "the code does not verify") },
			guidance.ReasonPasskeyRevoked: func() error { return s.passkeyRevoked(ctx, big) },
		} {
			te := testErrors().ToolError(refuse())
			require.Equal(t, guidance.CodeRevertInvalid, te.Code, name)
			stepcatalogtest.RequirePersonMessage(t, te.PersonMessage, te.Links)
			require.NotContains(t, te.PersonMessage, "#2.", "%s %q: no long link in the message", name, origin)
			var open *toolresult.NextStep
			for i := range te.NextSteps {
				step := te.NextSteps[i]
				require.NotEqual(t, toolresult.ActionSendRequest, step.Action, "%s %q: the file was sent with the request", name, origin)
				require.LessOrEqual(t, len(step.URL), links.DefaultBudget, "%s %q: no step carries a link over the budget", name, origin)
				if step.Action == toolresult.ActionOpenLink {
					open = &step
				}
			}
			require.NotNil(t, open, name)
			if origin != "" {
				require.Empty(t, open.URL, "%s: the short link the person has", name)
				require.Contains(t, open.Text, "short link the agent gave you earlier", name)
				continue
			}
			hash, _, err := links.HashLink(long, links.RevertFile(big.ID))
			require.NoError(t, err)
			require.Equal(t, hash, open.URL, "%s: the hash link the request handed over", name)
			require.Contains(t, open.Text, "request file the agent sent you earlier", name)
		}
	}
}

// A widened revert's refusal names no link: the person signs on the page
// they widened on (RS-5), whether or not the engine serves the pages.
func TestWidenedRevertInvalidNamesNoLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := revertOf(t, "Undo the bad merge", revertLines(2), false)
	r.Widened = true
	for _, origin := range []string{localPages, ""} {
		te := testErrors().ToolError(newService(t, "linux", "", pagesOrigin(origin), linkBudget(links.DefaultBudget)).badSignature(ctx, r, "m"))
		require.Equal(t, toolresult.ActionOpenLink, te.NextSteps[0].Action)
		require.Empty(t, te.NextSteps[0].URL, origin)
		require.NotContains(t, te.NextSteps[0].Text, "short link the agent gave you", origin)
	}
}

// requireSendRequestFirst checks a result over the budget: requestFile beside
// the hash link, and SEND_REQUEST first, then the catalog's steps, every
// step obeying the step rules.
func requireSendRequestFirst(t *testing.T, steps []toolresult.NextStep, file *links.RequestFile, where string) {
	t.Helper()
	require.NotNil(t, file, where)
	require.NotEmpty(t, steps, where)
	require.Equal(t, toolresult.ActorAgent, steps[0].Actor, where)
	require.Equal(t, toolresult.ActionSendRequest, steps[0].Action, where)
	require.Equal(t, guidance.SendRequestText(file), steps[0].Text, where)
	for i, st := range steps {
		stepcatalogtest.RequireStepObeysRules(t, st, stepcatalogtest.Case{Tool: guidance.ToolRequestRevert, Args: map[string]any{"runId": caseRunID, "intent": "Undo"}}, fmt.Sprintf("%s step %d", where, i+1))
	}
	require.NotEqual(t, toolresult.ActionSendRequest, stepcatalogtest.CatalogKinds(steps)[0].Action, "the catalog checks skip it")
}

// A revert's result over the budget, on an engine that serves no pages,
// carries requestFile and starts with SEND_REQUEST (CONTRACT.md, The request
// file and pasted blocks).
func TestHashLinkRevertResultsSendTheRequestFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newService(t, "linux", "", linkBudget(links.DefaultBudget))

	r := revertOf(t, "Undo the bad merge", revertLines(60), false)
	out, err := s.revertWithLink(ctx, r)
	require.NoError(t, err)
	require.Contains(t, out.RevertURL, "#h=")
	requireSendRequestFirst(t, out.NextSteps, out.RequestFile, "request_revert")

	p := &PendingRevert{Revert: r}
	require.NoError(t, s.PendingRevert(ctx, p, false))
	require.Contains(t, p.RevertURL, "#h=", "a restated link without pages is the hash link")
	requireSendRequestFirst(t, p.NextSteps, p.RequestFile, "list_pending revert")
	require.Equal(t, p.RevertURL, p.NextSteps[1].URL)
}

// With the pages served, a list_pending revert that only restates its link
// has no requestFile and its OPEN_LINK carries no url, even when the long
// link is over the budget.
func TestRestatedRevertLinkWhileServingPagesSendsNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newService(t, "linux", "", pagesOrigin(localPages), linkBudget(links.DefaultBudget))
	r := revertOf(t, "Undo the bad merge", revertLines(60), false)
	p := &PendingRevert{Revert: r}
	require.NoError(t, s.PendingRevert(ctx, p, false))
	require.Nil(t, p.RequestFile)
	require.Equal(t, toolresult.ActionOpenLink, p.NextSteps[0].Action)
	require.Empty(t, p.NextSteps[0].URL)
	require.Contains(t, p.RevertURL, "#2.", "the field keeps the long link")
}

// Every personMessage of a revert's states obeys the contract, without a
// database.
func TestRevertStateMessagesObeyTheContract(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for _, origin := range []string{localPages, ""} {
		s := newService(t, "linux", "", pagesOrigin(origin), linkBudget(links.DefaultBudget))
		for _, status := range []string{ledger.RevertApplied, ledger.RevertApplying, ledger.RevertExpired, ledger.RevertPending} {
			for _, batched := range []bool{false, true} {
				r := revertOf(t, "Undo", revertLines(3), batched)
				r.Status, r.ApplyBy = status, &at
				out, err := s.revertState(context.Background(), r)
				require.NoError(t, err)
				stepcatalogtest.RequirePersonMessage(t, out.PersonMessage, out.Links)
			}
		}
	}
}

// TestRevertPersonMessagesNameNoCommandWithALongConfigPath builds the revert
// personMessages that once offered a command named after --config, with a
// 252-character path: each stays within the limit and names no basalt
// command, since the person acts on a link (CONTRACT.md, Next steps).
func TestRevertPersonMessagesNameNoCommandWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	s := newService(t, "linux", long)
	scope := action.Scope{Kind: revert.ScopeTask, ID: uuid.New()}

	messages := map[string]string{}
	for _, tool := range []string{guidance.ToolPreviewRevert, guidance.ToolRequestRevert} {
		err := s.prepareTimeout(tool, scope, "57014")
		var te *toolresult.ToolError
		require.ErrorAs(t, err, &te)
		messages["timeout "+tool] = te.PersonMessage
	}
	err := s.nothingToRevertError(context.Background(), guidance.ToolPreviewRevert, scope, guidance.ReasonReadsOnly, "changed no rows")
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te)
	messages["nothing to revert, task"] = te.PersonMessage
	for _, st := range te.NextSteps {
		require.Empty(t, st.Command, "no command for other agents' changes in the task")
	}
	for name, m := range messages {
		require.NoError(t, guidance.CheckPersonMessage(m), "%s: %s", name, m)
		require.NotContains(t, m, long, name)
		require.NotContains(t, m, "basalt ", "%s: the person runs no command", name)
	}
}
