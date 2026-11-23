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

	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
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
		want        linksvc.HandOver
	}{
		{"a short link comes first", short, long, 1800, linksvc.HandOver{URL: short, Kind: linksvc.LinkShort}},
		{"a short link is never measured", short, long, 1, linksvc.HandOver{URL: short, Kind: linksvc.LinkShort}},
		{"a long link within the budget", "", long, 1800, linksvc.HandOver{URL: long, Kind: linksvc.LinkLong}},
		{"a long link at the budget", "", long, len(long), linksvc.HandOver{URL: long, Kind: linksvc.LinkLong}},
		{"a long link one over the budget becomes the hash link", "", long, len(long) - 1, linksvc.HandOver{URL: hash, Kind: linksvc.LinkHash, File: &file}},
		{"far over the budget", "", long, 1, linksvc.HandOver{URL: hash, Kind: linksvc.LinkHash, File: &file}},
	} {
		got, err := linksvc.ChooseLink(tc.short, tc.long, tc.budget, "f.txt")
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

func noticeService(origin string, budget int, opts ...func(*Deps)) *Service {
	d := deps()
	setApprovals(&d, catalogApprovals{})
	setReverts(&d, catalogReverts{})
	d.Core.PagesOrigin = origin
	d.Core.LinkBudget = budget
	for _, opt := range opts {
		opt(&d)
	}
	return NewService(d)
}

const localPages = "http://localhost:8787"

func approvalNoticeOf(t *testing.T, s *Service, rows int, issue bool) linksvc.HeldAnswer {
	t.Helper()
	n, err := s.approval.approvalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), linksvc.SizedRequest{Binding: noticeBinding, Lines: bigLines(rows)},
		time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), issue)
	require.NoError(t, err)
	stepcatalogtest.RequirePersonMessage(t, n.PersonMessage, n.Links)
	return n
}

func TestApprovalNoticeHandsOverTheShortLinkFirst(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService(localPages, 1), 60, linksvc.IssueLink)

	require.Equal(t, n.ShortURL, n.ApprovalURL, "approvalUrl is the link handed over")
	require.Contains(t, n.ShortURL, "#s=")
	require.Contains(t, n.PersonMessage, "\n\n"+n.ShortURL+"\n\n")
	require.NotContains(t, n.PersonMessage, "#2.", "the long link stays out of the message")
	require.Equal(t, []toolresult.Link{{Label: "Approve the held write", URL: n.ShortURL}}, n.Links)
	require.NotContains(t, n.PersonMessage, "basalt ", "the person runs no command")
	require.NotContains(t, n.PersonMessage, "long", "no warning with a short link")
}

func TestApprovalNoticeHandsOverALongLinkWithinTheBudget(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService("", links.DefaultBudget), 3, linksvc.IssueLink)

	require.Empty(t, n.ShortURL)
	require.LessOrEqual(t, len(n.LongURL), links.DefaultBudget)
	require.Equal(t, n.LongURL, n.ApprovalURL)
	require.Contains(t, n.PersonMessage, "\n\n"+n.LongURL+"\n\n")
	require.Equal(t, []toolresult.Link{{Label: "Approve the held write", URL: n.LongURL}}, n.Links)
	require.NotContains(t, n.PersonMessage, "basalt ", "the person runs no command")
	require.NotContains(t, n.PersonMessage, "may arrive", "no warning within the budget")
}

func TestApprovalNoticeHandsOverTheHashLinkOverTheBudget(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService("", links.DefaultBudget), 60, linksvc.IssueLink)

	require.Greater(t, len(n.LongURL), links.DefaultBudget, "the fixture must be over budget")
	hash, file, err := links.HashLink(n.LongURL, links.ApprovalFile(uuid.MustParse(caseApproval)))
	require.NoError(t, err)
	require.Equal(t, hash, n.ApprovalURL, "the hash link stands in for the long link")
	require.Less(t, len(n.ApprovalURL), 120, "about 110 characters")
	require.Regexp(t, `/approvals/`+caseApproval+`#h=[A-Za-z0-9_-]{22}$`, n.ApprovalURL)
	require.Equal(t, &file, n.RequestFile)
	require.Equal(t, n.LongURL[strings.Index(n.LongURL, "#")+1:], n.RequestFile.Text, "the file carries the long link's request")
	require.NotEmpty(t, n.RequestFile.Blocks)
	require.NotContains(t, n.PersonMessage, "#2.", "no result hands over a long link over the budget")
	require.Contains(t, n.PersonMessage, "open the request file the agent sends you (or paste its text blocks)")
	require.Contains(t, n.PersonMessage, "\n\n"+n.ApprovalURL+"\n\n")
	require.NotContains(t, n.PersonMessage, "basalt ", "the person runs no command")
	require.Equal(t, []toolresult.Link{{Label: "Approve the held write", URL: n.ApprovalURL}}, n.Links)
}

func TestApprovalNoticeWithinTheBudgetCarriesNoRequestFile(t *testing.T) {
	t.Parallel()
	require.Nil(t, approvalNoticeOf(t, noticeService("", links.DefaultBudget), 3, linksvc.IssueLink).RequestFile)
	require.Nil(t, approvalNoticeOf(t, noticeService(localPages, 1), 60, linksvc.IssueLink).RequestFile, "a short link")
	require.Nil(t, approvalNoticeOf(t, noticeService(localPages, links.DefaultBudget), 60, linksvc.KeepLink).RequestFile,
		"a restated link while the pages are served")
}

func TestApprovalNoticeWithoutANewLinkAddsNoURL(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService(localPages, links.DefaultBudget), 60, linksvc.KeepLink)

	require.Empty(t, n.ShortURL, "the engine keeps only the hash of the link it gave")
	require.NotContains(t, n.PersonMessage, "http", "the person has the link the agent gave them")
	require.Empty(t, n.Links)
	require.Contains(t, n.PersonMessage, "Approve with the link you were given.")
	require.NotContains(t, n.PersonMessage, "basalt ", "the person runs no command")
}

func TestApprovalNoticeStaysWithin500CharactersWhateverIsLong(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("a_rather_long_agent_name_for_a_bot", "/Users/someone/Library/Application Support/Basalt/with/a/deep/path/engine.json", "darwin", testManager())
	require.NoError(t, err)
	lines := make([]string, 0, 40)
	for i := range 40 { // many cascaded tables with long names make a long headline
		lines = append(lines, fmt.Sprintf(`{"op": "DELETE", "key": {"id": %d}, "old": {"id": %d}, "set": null, "table": "some_schema_%d.a_table_with_a_long_name_%d", "cascaded": true}`, i, i, i, i))
	}
	lines = append(lines, bigLines(3)...)
	for _, origin := range []string{localPages, ""} {
		s := noticeService(origin, 1, func(d *Deps) { d.Core.Commands = cmds })
		n, err := s.approval.approvalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), linksvc.SizedRequest{Binding: noticeBinding, Lines: lines},
			time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), linksvc.IssueLink)
		require.NoError(t, err)
		stepcatalogtest.RequirePersonMessage(t, n.PersonMessage, n.Links)
	}
}

// TestPersonMessagesNameNoCommandWithALongConfigPath builds the
// personMessages that once offered a command named after --config, with a
// 252-character path: each stays within the limit and names no basalt
// command, since the person acts on a link (CONTRACT.md, Next steps).
func TestPersonMessagesNameNoCommandWithALongConfigPath(t *testing.T) {
	t.Parallel()
	long := "/" + strings.Repeat("a-long-directory-name-of-sixty-characters-in-total-ok-ok-ok-", 4) + "engine.json"
	cmds, err := NewCommands("pbot", long, "linux", testManager())
	require.NoError(t, err)
	s := &Service{deps: Deps{Core: CoreDeps{Commands: cmds, Log: slog.New(slog.DiscardHandler)}}}
	s.wire()

	messages := map[string]string{}
	messages["not granted"] = newDescribeCase(&s.deps.Core, &DescribeDeps{}, nil).notGrantedSteps(guidance.NewSteps(), 12)
	messages["describe not found"] = newDescribeCase(&s.deps.Core, &DescribeDeps{}, nil).describeNotFoundSteps(guidance.NewSteps(), failure{tool: toolDescribe})
	rls := &Service{deps: Deps{Core: CoreDeps{Commands: cmds, Log: slog.New(slog.DiscardHandler)}}}
	rls.wire()
	w, err := rls.write.rlsWarning("public." + strings.Repeat("t", 60))
	require.NoError(t, err)
	messages["rls warning"] = w.PersonMessage
	messages["wait"], _ = waitMessage("Held for your approval: "+strings.Repeat("x", 96)+".", time.Now().Add(time.Hour))

	for name, m := range messages {
		require.NoError(t, guidance.CheckPersonMessage(m), "%s: %s", name, m)
		require.NotContains(t, m, long, name)
		require.NotContains(t, m, "basalt ", "%s: the person runs no command", name)
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
		stepcatalogtest.RequireStepObeysRules(t, st, stepcatalogtest.Case{Tool: guidance.ToolWrite, Args: writeArgs0}, fmt.Sprintf("%s step %d", where, i+1))
	}
	require.NotEqual(t, toolresult.ActionSendRequest, stepcatalogtest.CatalogKinds(steps)[0].Action, "the catalog checks skip it")
}

// TestHashLinkResultsSendTheRequestFirst: on an engine that serves no pages,
// every result that hands over a hash link carries requestFile and starts
// with SEND_REQUEST (CONTRACT.md, The request file and pasted blocks).
func TestHashLinkResultsSendTheRequestFirst(t *testing.T) {
	t.Parallel()
	s := noticeService("", links.DefaultBudget)

	n := approvalNoticeOf(t, s, 60, linksvc.IssueLink)
	te := s.Failure(guidance.ToolWrite, writeArgs0, approvalRequiredError(n))
	require.Same(t, n.RequestFile, te.Approval.RequestFile)
	requireSendRequestFirst(t, te.NextSteps, te.Approval.RequestFile, "write held")

	item := PendingItem{Notice: n.ApprovalNotice}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.deps.Core.Now().Add(time.Hour)
	_, _, steps, err := s.approval.itemGuidance(item)
	require.NoError(t, err)
	requireSendRequestFirst(t, steps, item.Notice.RequestFile, "list_pending approval")
}

// TestRestatedLinksWhileServingPagesSendNothing: with the pages served, a
// list_pending item that only restates its link has no requestFile and its
// OPEN_LINK carries no url, even when the long link is over the budget.
func TestRestatedLinksWhileServingPagesSendNothing(t *testing.T) {
	t.Parallel()
	s := noticeService(localPages, links.DefaultBudget)
	n := approvalNoticeOf(t, s, 60, linksvc.KeepLink)
	item := PendingItem{Notice: n.ApprovalNotice, Restated: true}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.deps.Core.Now().Add(time.Hour)
	_, _, steps, err := s.approval.itemGuidance(item)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	require.Equal(t, toolresult.ActionOpenLink, steps[0].Action)
	require.Empty(t, steps[0].URL)
}

// TestExpiredItemsCarryNoRequestFile: a held write that no longer waits for
// the person has nothing to send.
func TestExpiredItemsCarryNoRequestFile(t *testing.T) {
	t.Parallel()
	s := noticeService("", links.DefaultBudget)
	n := approvalNoticeOf(t, s, 60, linksvc.IssueLink)
	require.NotNil(t, n.RequestFile)
	item := PendingItem{Notice: n.ApprovalNotice}
	item.Status, item.ExpiresAt = ledger.ApprovalPending, s.deps.Core.Now().Add(-time.Hour)
	require.False(t, s.approval.waitsForPerson(item))
	item.Status, item.ExpiresAt = ledger.ApprovalApproved, s.deps.Core.Now().Add(time.Hour)
	require.False(t, s.approval.waitsForPerson(item))
}

// APPROVAL_INVALID sends the person back to the page the hold handed over:
// with the pages served, to the short link they have (no url, no long link
// over the budget); without them, to the hash link, naming the request file
// the agent already sent.
func TestApprovalInvalidRestatesTheHoldsLink(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{localPages, ""} {
		s := noticeService(origin, links.DefaultBudget)
		n := approvalNoticeOf(t, s, 60, linksvc.KeepLink)
		te := s.approvalLinkError(&toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Reason: guidance.ReasonNotSigned, Message: "m"}, n)
		stepcatalogtest.RequirePersonMessage(t, te.PersonMessage, te.Links)
		require.NotContains(t, te.PersonMessage, "#2.", "%s: no long link over the budget", origin)
		open := te.NextSteps[0]
		require.Equal(t, toolresult.ActionOpenLink, open.Action)
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
