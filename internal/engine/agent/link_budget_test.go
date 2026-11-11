package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func TestChooseLink(t *testing.T) {
	t.Parallel()
	const short, long = "http://localhost:8787/approvals/1#s=abc", "http://localhost:8787/approvals/1#2.abcdef"
	for _, tc := range []struct {
		name        string
		short, long string
		budget      int
		want        handOver
	}{
		{"a short link comes first", short, long, 1800, handOver{short, linkShort}},
		{"a short link is never measured", short, long, 1, handOver{short, linkShort}},
		{"a long link within the budget", "", long, 1800, handOver{long, linkLong}},
		{"a long link at the budget", "", long, len(long), handOver{long, linkLong}},
		{"a long link one over the budget", "", long, len(long) - 1, handOver{long, linkOverBudget}},
		{"the interim hand-over of an over-budget link (VC-28)", "", long, 1, handOver{long, linkOverBudget}},
	} {
		require.Equal(t, tc.want, chooseLink(tc.short, tc.long, tc.budget), tc.name)
	}
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

func TestApprovalNoticeWarnsBeforeAnOverBudgetLongLink(t *testing.T) {
	t.Parallel()
	n := approvalNoticeOf(t, noticeService("", links.DefaultBudget), 60, issueLink)

	require.Greater(t, len(n.longURL), links.DefaultBudget, "the fixture must be over budget")
	require.Equal(t, n.longURL, n.ApprovalURL, "VC-28: the over-budget long link is still handed over")
	lines := strings.Split(n.PersonMessage, "\n")
	require.Contains(t, lines[0], "long and may arrive cut or broken", "the warning comes first")
	require.Contains(t, lines[1], n.ApproveCommand, "then the command")
	require.True(t, strings.HasSuffix(n.PersonMessage, "\n\n"+n.longURL+"\n\n"+lines[len(lines)-1]) ||
		strings.HasSuffix(n.PersonMessage, "\n\n"+n.longURL), "then the link")
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: n.longURL}}, n.Links)
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
	binding := fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "scope": "RUN", "agents": ["basalt_agent_bot"], "intent": %q, "scopeId": %q, "skipped": 0, `+
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
	require.NotContains(t, short.Message, "may arrive")
	requirePersonMessage(t, short.Message, short.Links)

	within, err := noticeService("", links.DefaultBudget).revertNotice(ctx, small)
	require.NoError(t, err)
	require.Contains(t, within.URL, "#2.")
	require.LessOrEqual(t, len(within.URL), links.DefaultBudget)
	require.NotContains(t, within.Message, "may arrive")
	require.Equal(t, []mcp.Link{{Label: "Review and sign the revert", URL: within.URL}}, within.Links)
	requirePersonMessage(t, within.Message, within.Links)

	over, err := noticeService("", links.DefaultBudget).revertNotice(ctx, big)
	require.NoError(t, err)
	require.Greater(t, len(over.URL), links.DefaultBudget, "the fixture must be over budget")
	require.Contains(t, strings.Split(over.Message, "\n")[0], "long and may arrive cut or broken", "the warning comes first")
	require.Contains(t, over.Message, "\n\n"+over.URL, "VC-28: the over-budget long link is still handed over, in revertUrl and in the message")
	require.NotContains(t, over.Message, "basalt revert", "a revert gets only the warning (VC-28)")
	require.Equal(t, []mcp.Link{{Label: "Review and sign the revert", URL: over.URL}}, over.Links)
	requirePersonMessage(t, over.Message, over.Links)
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
