package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

func TestChooseLink(t *testing.T) {
	t.Parallel()
	const short, long = "http://localhost:8787/approvals/1#s=abc", "http://localhost:8787/approvals/1#2.abcdef"
	hash, file, err := links.HashLink(long, "f.txt")
	require.NoError(t, err)
	for _, tc := range []struct {
		name        string
		short, long string
		budget      int
		want        handOver
	}{
		{"a short link comes first", short, long, 1800, handOver{URL: short, Kind: linkShort}},
		{"a short link is never measured", short, long, 1, handOver{URL: short, Kind: linkShort}},
		{"a long link within the budget", "", long, 1800, handOver{URL: long, Kind: linkLong}},
		{"a long link at the budget", "", long, len(long), handOver{URL: long, Kind: linkLong}},
		{"a long link one over the budget becomes the hash link", "", long, len(long) - 1, handOver{URL: hash, Kind: linkHash, File: &file}},
		{"far over the budget", "", long, 1, handOver{URL: hash, Kind: linkHash, File: &file}},
	} {
		got, err := chooseLink(tc.short, tc.long, tc.budget, "f.txt")
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
	require.Equal(t, "http://localhost:8787/approvals/1#h="+links.RequestHash("2.abcdef"), hash)
}

// bigLines are n distinct approval preview lines that do not compress, so a
// link over them is long.
func bigLines(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		sum := sha256.Sum256(fmt.Appendf(nil, "row %d", i))
		sum2 := sha256.Sum256(sum[:])
		out = append(out, fmt.Sprintf(`{"op": "DELETE", "key": {"id": %d}, "old": {"id": %d, "note": "%s%s"}, "set": null, "table": "public.leads", "cascaded": false}`,
			i, i, hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:])))
	}
	return out
}

const noticeBinding = `{"kind": "APPROVE", "rows": 3, "agent": "basalt_agent_bot", "runId": "` + caseRunID + `", "intent": "Remove the spam lead", ` +
	`"params": [], "database": "app", "rowsHash": "3c4e241b3edf41860015fee8ec777698cd66631ddd185902261f9256a8a5bfa4", ` +
	`"expiresAt": "2026-11-12T06:02:11.123456Z", "statement": "DELETE FROM public.leads", "approvalId": "` + caseApproval + `", "assignedColumns": []}`

func noticeService(origin string, budget int) *Service {
	d := deps()
	d.Approvals = catalogApprovals{}
	d.Reverts = catalogReverts{}
	d.PagesOrigin = origin
	d.LinkBudget = budget
	return NewService(d)
}

const localPages = "http://localhost:8787"

func approvalNoticeOf(t *testing.T, s *Service, rows int, issue bool) heldNotice {
	t.Helper()
	n, err := s.approvalNotice(context.Background(), uuid.MustParse(caseApproval), noticeBinding, bigLines(rows),
		time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), issue)
	require.NoError(t, err)
	requirePersonMessage(t, n.PersonMessage, n.Links)
	return n
}

func TestApprovalNoticeHandsOverTheShortLinkFirst(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService(localPages, 1), 60, issueLink)

	require.Equal(t, n.shortURL, n.ApprovalURL, "approvalUrl is the link handed over")
	require.Contains(t, n.shortURL, "#s=")
	require.Contains(t, n.PersonMessage, "\n\n"+n.shortURL+"\n\n")
	require.NotContains(t, n.PersonMessage, "#2.", "the long link stays out of the message")
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: n.shortURL}}, n.Links)
	require.Contains(t, n.PersonMessage, "Or run: "+n.ApproveCommand)
	require.NotContains(t, n.PersonMessage, "long", "no warning with a short link")
}

func TestApprovalNoticeHandsOverALongLinkWithinTheBudget(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService("", links.DefaultBudget), 3, issueLink)

	require.Empty(t, n.shortURL)
	require.LessOrEqual(t, len(n.longURL), links.DefaultBudget)
	require.Equal(t, n.longURL, n.ApprovalURL)
	require.Contains(t, n.PersonMessage, "\n\n"+n.longURL+"\n\n")
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: n.longURL}}, n.Links)
	require.Contains(t, n.PersonMessage, "Or run: "+n.ApproveCommand)
	require.NotContains(t, n.PersonMessage, "may arrive", "no warning within the budget")
}

func TestApprovalNoticeHandsOverTheHashLinkOverTheBudget(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService("", links.DefaultBudget), 60, issueLink)

	require.Greater(t, len(n.longURL), links.DefaultBudget, "the fixture must be over budget")
	hash, file, err := links.HashLink(n.longURL, links.ApprovalFile(uuid.MustParse(caseApproval)))
	require.NoError(t, err)
	require.Equal(t, hash, n.ApprovalURL, "the hash link stands in for the long link")
	require.Less(t, len(n.ApprovalURL), 120, "about 110 characters")
	require.Regexp(t, `/approvals/`+caseApproval+`#h=[A-Za-z0-9_-]{22}$`, n.ApprovalURL)
	require.Equal(t, &file, n.RequestFile)
	require.Equal(t, n.longURL[strings.Index(n.longURL, "#")+1:], n.RequestFile.Text, "the file carries the long link's request")
	require.NotEmpty(t, n.RequestFile.Blocks)
	require.NotContains(t, n.PersonMessage, "#2.", "no result hands over a long link over the budget")
	require.Contains(t, n.PersonMessage, "open the request file the agent sends you (or paste its text blocks)")
	require.Contains(t, n.PersonMessage, "\n\n"+n.ApprovalURL+"\n\n")
	require.Contains(t, n.PersonMessage, "Or run: "+n.ApproveCommand)
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: n.ApprovalURL}}, n.Links)
}

func TestApprovalNoticeWithinTheBudgetCarriesNoRequestFile(t *testing.T) {
	t.Parallel()
	require.Nil(t, approvalNoticeOf(t, noticeService("", links.DefaultBudget), 3, issueLink).RequestFile)
	require.Nil(t, approvalNoticeOf(t, noticeService(localPages, 1), 60, issueLink).RequestFile, "a short link")
	require.Nil(t, approvalNoticeOf(t, noticeService(localPages, links.DefaultBudget), 60, keepLink).RequestFile,
		"a restated link while the pages are served")
}

func TestApprovalNoticeWithoutANewLinkAddsNoURL(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService(localPages, links.DefaultBudget), 60, keepLink)

	require.Empty(t, n.shortURL, "the engine keeps only the hash of the link it gave")
	require.NotContains(t, n.PersonMessage, "http", "the person has the link the agent gave them")
	require.Empty(t, n.Links)
	require.Contains(t, n.PersonMessage, n.ApproveCommand)
}

func TestApprovalNoticeStaysWithin500CharactersWhateverIsLong(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("a_rather_long_agent_name_for_a_bot", "/Users/someone/Library/Application Support/Basalt/with/a/deep/path/engine.json", "darwin", nil)
	require.NoError(t, err)
	lines := make([]string, 0, 40)
	for i := range 40 { // many cascaded tables with long names make a long headline
		lines = append(lines, fmt.Sprintf(`{"op": "DELETE", "key": {"id": %d}, "old": {"id": %d}, "set": null, "table": "some_schema_%d.a_table_with_a_long_name_%d", "cascaded": true}`, i, i, i, i))
	}
	lines = append(lines, bigLines(3)...)
	for _, origin := range []string{localPages, ""} {
		s := noticeService(origin, 1)
		s.Commands = cmds
		n, err := s.approvalNotice(context.Background(), uuid.MustParse(caseApproval), noticeBinding, lines,
			time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), issueLink)
		require.NoError(t, err)
		requirePersonMessage(t, n.PersonMessage, n.Links)
	}
}

func revertOf(t *testing.T, intent string, lines []string, batched bool) ledger.Revert {
	t.Helper()
	rows := len(lines)
	binding := fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "intent": %q, "select": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": null, "scopeId": %q}, "skipped": 0, "widened": false, `+
		`"database": "app", "revertId": %q, "rowsHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80", `+
		`"expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "basalt_agent_bot"}`, rows, intent, caseRunID, caseRevertID)
	if batched {
		binding = strings.Replace(binding, `"skipped": 0`, `"skipped": 0, "batched": true, "sampleHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80"`, 1)
		binding = strings.Replace(binding, fmt.Sprintf(`"rows": %d`, rows), `"rows": 1200`, 1)
	}
	r := caseRevert(false)
	r.Rows, r.BindingText, r.Lines, r.Batched = rows, binding, lines, batched
	return r
}

func revertLines(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		sum := sha256.Sum256(fmt.Appendf(nil, "restore %d", i))
		sum2 := sha256.Sum256(sum[:])
		out = append(out, fmt.Sprintf(`{"op": "INSERT", "key": {"id": %d}, "now": null, "set": {"id": %d, "note": "%s%s"}, "table": "public.leads", `+
			`"action": "RESTORE", "cascaded": false, "conflict": null, "sqlState": null, "changeIds": ["%s"]}`,
			i, i, hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:]), caseChangeID))
	}
	return out
}

func TestRevertNoticeFollowsTheHandOverOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	small, big := revertOf(t, "Undo the bad merge", revertLines(2), false), revertOf(t, "Undo the bad merge", revertLines(60), false)

	short, err := noticeService(localPages, 1).revertNotice(ctx, big)
	require.NoError(t, err)
	require.Contains(t, short.URL, "#s=", "a short link is never measured")
	require.Equal(t, []mcp.Link{{Label: "Review and sign the revert", URL: short.URL}}, short.Links)
	require.Contains(t, short.Message, "\n\n"+short.URL)
	require.Nil(t, short.File)
	requirePersonMessage(t, short.Message, short.Links)

	within, err := noticeService("", links.DefaultBudget).revertNotice(ctx, small)
	require.NoError(t, err)
	require.Contains(t, within.URL, "#2.")
	require.LessOrEqual(t, len(within.URL), links.DefaultBudget)
	require.Nil(t, within.File)
	require.Equal(t, []mcp.Link{{Label: "Review and sign the revert", URL: within.URL}}, within.Links)
	requirePersonMessage(t, within.Message, within.Links)

	over, err := noticeService("", links.DefaultBudget).revertNotice(ctx, big)
	require.NoError(t, err)
	require.Greater(t, len(over.long), links.DefaultBudget, "the fixture must be over budget")
	require.Regexp(t, `/reverts/`+caseRevertID+`#h=[A-Za-z0-9_-]{22}$`, over.URL)
	require.NotNil(t, over.File)
	require.Equal(t, links.RevertFile(uuid.MustParse(caseRevertID)), over.File.FileName)
	require.Equal(t, links.RequestHash(over.File.Text), over.URL[strings.Index(over.URL, "#h=")+3:])
	require.Contains(t, over.Message, "Sign it with your passkey: open this link, then open the request file the agent sends you")
	require.Contains(t, over.Message, "\n\n"+over.URL)
	require.NotContains(t, over.Message, "#2.")
	require.Equal(t, []mcp.Link{{Label: "Review and sign the revert", URL: over.URL}}, over.Links)
	requirePersonMessage(t, over.Message, over.Links)
}

// TestRevertNoticeNamesOnlyTheFileWithoutBlocks: a request too long for ten
// blocks goes as a file only, and the message says so.
func TestRevertNoticeNamesOnlyTheFileWithoutBlocks(t *testing.T) {
	t.Parallel()
	huge := revertOf(t, "Undo the bad merge", revertLines(200), false)
	n, err := noticeService("", links.DefaultBudget).revertNotice(context.Background(), huge)
	require.NoError(t, err)
	require.NotNil(t, n.File)
	require.Greater(t, len(n.File.Text), links.RequestPieceChars*links.RequestMaxBlocks, "the fixture must need more than ten blocks")
	require.Nil(t, n.File.Blocks)
	require.Contains(t, n.Message, "open the request file the agent sends you. The page")
	require.NotContains(t, n.Message, "text blocks")
	requirePersonMessage(t, n.Message, n.Links)
}

func TestRevertNoticeStaysWithin500CharactersWhateverIsLong(t *testing.T) {
	t.Parallel()
	intent := strings.Repeat("Undo the bad merge of the leads. ", 15) // 495 characters, the tool's limit is 500
	for _, batched := range []bool{false, true} {
		for _, origin := range []string{localPages, ""} {
			r := revertOf(t, intent, revertLines(60), batched)
			n, err := noticeService(origin, 1).revertNotice(context.Background(), r)
			require.NoError(t, err)
			requirePersonMessage(t, n.Message, n.Links)
		}
	}
}

// TestApprovalMessageStaysWithinTheLimitWithALongConfigPath: the approve
// command names --config, so a long path would push the message over 500
// characters; the message then points to the command in the step instead.
func TestApprovalMessageStaysWithinTheLimitWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	cmds, err := NewCommands("pbot", long, "linux", nil)
	require.NoError(t, err)
	id := uuid.New()
	command := cmds.Approve(id)
	require.Contains(t, command, long)
	lead := "Held for your approval: " + strings.Repeat("Delete 1 row in a table with many cascaded rows ", 2)[:96] + "."
	for _, pick := range []handOver{
		{URL: "https://portal.basaltvault.app/approvals/" + id.String() + "#s=q3Jv8sLk2mT0xYp1aBcD9w", Kind: linkShort},
		{URL: "https://portal.basaltvault.app/approvals/" + id.String() + "#h=q3Jv8sLk2mT0xYp1aBcD9w", Kind: linkHash, File: &links.RequestFile{Blocks: []string{"b"}}},
	} {
		text, _ := approvalMessage(lead, pick, command, "Expires 2026-11-12 07:02 UTC.")
		require.NoError(t, CheckPersonMessage(text), text)
		require.Contains(t, text, "approve command the agent shows you")
		require.NotContains(t, text, long)
	}

	// A short path keeps the command in the message.
	short, err := NewCommands("pbot", "/etc/basalt/engine.json", "linux", nil)
	require.NoError(t, err)
	text, _ := approvalMessage(lead, handOver{URL: "https://portal.basaltvault.app/approvals/" + id.String() + "#s=q3Jv8sLk2mT0xYp1aBcD9w", Kind: linkShort}, short.Approve(id))
	require.Contains(t, text, short.Approve(id))
}

// TestMessagesOfferingACommandStayWithinTheLimitWithALongConfigPath builds
// every personMessage that carries a command named after --config with a
// 252-character path.
func TestMessagesOfferingACommandStayWithinTheLimitWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	cmds, err := NewCommands("pbot", long, "linux", nil)
	require.NoError(t, err)
	s := &Service{Deps: Deps{Commands: cmds, Log: slog.New(slog.DiscardHandler)}}
	scope := guard.RevertScope{Kind: revert.ScopeTask, ID: uuid.New()}

	messages := map[string]string{}
	for _, tool := range []string{toolPreviewRevert, toolRequestRevert} {
		err := s.prepareTimeout(tool, scope, "57014")
		var te *mcp.ToolError
		require.ErrorAs(t, err, &te)
		messages["timeout "+tool] = te.PersonMessage
	}
	err = s.nothingToRevertError(context.Background(), toolPreviewRevert, scope, reasonReadsOnly, "changed no rows")
	var te *mcp.ToolError
	require.ErrorAs(t, err, &te)
	messages["nothing to revert, task"] = te.PersonMessage
	require.Equal(t, cmds.Revert(scope), te.NextSteps[len(te.NextSteps)-1].Command, "the command stays in a PERSON step")
	messages["not granted"] = s.notGrantedSteps(NewSteps(), 12)
	messages["describe not found"] = s.describeNotFoundSteps(NewSteps(), failure{tool: toolDescribe})
	rls := &Service{Deps: Deps{Commands: cmds, Log: slog.New(slog.DiscardHandler)}}
	w, err := rls.rlsWarning("public." + strings.Repeat("t", 60))
	require.NoError(t, err)
	messages["rls warning"] = w.PersonMessage
	messages["wait"], _ = waitMessage("Held for your approval: "+strings.Repeat("x", 96)+".", cmds.Approve(uuid.New()), time.Now().Add(time.Hour))

	for name, m := range messages {
		require.NoError(t, CheckPersonMessage(m), "%s: %s", name, m)
	}
	// The preview timeout holds two commands: it must have been cut.
	require.Contains(t, messages["timeout "+toolPreviewRevert], commandElsewhere)
}

// requireSendRequestFirst checks a result over the budget: requestFile beside
// the hash link, and SEND_REQUEST first, then the catalog's steps, every
// step obeying the step rules.
func requireSendRequestFirst(t *testing.T, steps []mcp.NextStep, file *links.RequestFile, where string) {
	t.Helper()
	require.NotNil(t, file, where)
	require.NotEmpty(t, steps, where)
	require.Equal(t, mcp.ActorAgent, steps[0].Actor, where)
	require.Equal(t, mcp.ActionSendRequest, steps[0].Action, where)
	require.Equal(t, sendRequestText(file), steps[0].Text, where)
	for i, st := range steps {
		requireStepObeysRules(t, st, catalogCase{tool: toolWrite, args: writeArgs0}, "", fmt.Sprintf("%s step %d", where, i+1))
	}
	require.NotEqual(t, mcp.ActionSendRequest, catalogKinds(steps)[0].Action, "the catalog checks skip it")
}

// TestHashLinkResultsSendTheRequestFirst: on an engine that serves no pages,
// every result that hands over a hash link carries requestFile and starts
// with SEND_REQUEST (CONTRACT.md, The request file and pasted blocks).
func TestHashLinkResultsSendTheRequestFirst(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := noticeService("", links.DefaultBudget)

	n := approvalNoticeOf(t, s, 60, issueLink)
	te := s.Failure(toolWrite, writeArgs0, approvalRequiredError(n))
	require.Same(t, n.RequestFile, te.Approval.RequestFile)
	requireSendRequestFirst(t, te.NextSteps, te.Approval.RequestFile, "write held")

	r := revertOf(t, "Undo the bad merge", revertLines(60), false)
	out, err := s.revertWithLink(ctx, r)
	require.NoError(t, err)
	require.Contains(t, out.RevertURL, "#h=")
	requireSendRequestFirst(t, out.NextSteps, out.RequestFile, "request_revert")

	p := &PendingRevert{Revert: r}
	require.NoError(t, s.pendingRevert(ctx, p, false))
	require.Contains(t, p.RevertURL, "#h=", "a restated link without pages is the hash link")
	requireSendRequestFirst(t, p.NextSteps, p.RequestFile, "list_pending revert")
	require.Equal(t, p.RevertURL, p.NextSteps[1].URL)

	item := PendingItem{Notice: n.ApprovalNotice}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.Now().Add(time.Hour)
	_, _, steps, err := s.itemGuidance(item)
	require.NoError(t, err)
	requireSendRequestFirst(t, steps, item.Notice.RequestFile, "list_pending approval")
}

// TestRestatedLinksWhileServingPagesSendNothing: with the pages served, a
// list_pending item that only restates its link has no requestFile and its
// OPEN_LINK carries no url, even when the long link is over the budget.
func TestRestatedLinksWhileServingPagesSendNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := noticeService(localPages, links.DefaultBudget)
	r := revertOf(t, "Undo the bad merge", revertLines(60), false)
	p := &PendingRevert{Revert: r}
	require.NoError(t, s.pendingRevert(ctx, p, false))
	require.Nil(t, p.RequestFile)
	require.Equal(t, mcp.ActionOpenLink, p.NextSteps[0].Action)
	require.Empty(t, p.NextSteps[0].URL)
	require.Contains(t, p.RevertURL, "#2.", "the field keeps the long link")

	n := approvalNoticeOf(t, s, 60, keepLink)
	item := PendingItem{Notice: n.ApprovalNotice, Restated: true}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.Now().Add(time.Hour)
	_, _, steps, err := s.itemGuidance(item)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	require.Equal(t, mcp.ActionOpenLink, steps[0].Action)
	require.Empty(t, steps[0].URL)
}

// TestExpiredItemsCarryNoRequestFile: a held write that no longer waits for
// the person has nothing to send.
func TestExpiredItemsCarryNoRequestFile(t *testing.T) {
	t.Parallel()
	s := noticeService("", links.DefaultBudget)
	n := approvalNoticeOf(t, s, 60, issueLink)
	require.NotNil(t, n.RequestFile)
	item := PendingItem{Notice: n.ApprovalNotice}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.Now().Add(-time.Hour)
	require.False(t, s.waitsForPerson(item))
	item.Status, item.ExpiresAt = ledger.ApprovalApproved, s.Now().Add(time.Hour)
	require.False(t, s.waitsForPerson(item))
}

// APPROVAL_INVALID sends the person back to the page the hold handed over:
// with the pages served, to the short link they have (no url, no long link
// over the budget); without them, to the hash link, naming the request file
// the agent already sent.
func TestApprovalInvalidRestatesTheHoldsLink(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{localPages, ""} {
		s := noticeService(origin, links.DefaultBudget)
		n := approvalNoticeOf(t, s, 60, keepLink)
		te := s.approvalLinkError(&mcp.ToolError{Code: CodeApprovalInvalid, Reason: reasonNotSigned, Message: "m"}, n)
		requirePersonMessage(t, te.PersonMessage, te.Links)
		require.NotContains(t, te.PersonMessage, "#2.", "%s: no long link over the budget", origin)
		open := te.NextSteps[0]
		require.Equal(t, mcp.ActionOpenLink, open.Action)
		if origin != "" {
			require.Empty(t, open.URL, "the short link the person has")
			require.Empty(t, te.Links)
			require.Contains(t, te.PersonMessage, "Approve with the link you were given")
			continue
		}
		require.Contains(t, open.URL, "#h=")
		require.Contains(t, te.PersonMessage, "the request file the agent sent you earlier")
		require.NotContains(t, te.PersonMessage, "sends you")
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
		s := noticeService(origin, links.DefaultBudget)
		long, err := s.longRevertLink(ctx, big)
		require.NoError(t, err)
		require.Greater(t, len(long), links.DefaultBudget, "the fixture must be over budget")
		for name, refuse := range map[string]func() error{
			reasonBadSignature:   func() error { return s.badSignature(ctx, big, "the code does not verify") },
			reasonPasskeyRevoked: func() error { return s.passkeyRevoked(ctx, big) },
		} {
			te := ToolError(refuse())
			require.Equal(t, CodeRevertInvalid, te.Code, name)
			requirePersonMessage(t, te.PersonMessage, te.Links)
			require.NotContains(t, te.PersonMessage, "#2.", "%s %q: no long link in the message", name, origin)
			var open *mcp.NextStep
			for i := range te.NextSteps {
				step := te.NextSteps[i]
				require.NotEqual(t, mcp.ActionSendRequest, step.Action, "%s %q: the file was sent with the request", name, origin)
				require.LessOrEqual(t, len(step.URL), links.DefaultBudget, "%s %q: no step carries a link over the budget", name, origin)
				if step.Action == mcp.ActionOpenLink {
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
		te := ToolError(noticeService(origin, links.DefaultBudget).badSignature(ctx, r, "m"))
		require.Equal(t, mcp.ActionOpenLink, te.NextSteps[0].Action)
		require.Empty(t, te.NextSteps[0].URL, origin)
		require.NotContains(t, te.NextSteps[0].Text, "short link the agent gave you", origin)
	}
}
