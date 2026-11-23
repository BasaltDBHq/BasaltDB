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
	n, err := s.approval.ApprovalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), linksvc.SizedRequest{Binding: noticeBinding, Lines: bigLines(rows)},
		time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC), issue)
	require.NoError(t, err)
	stepcatalogtest.RequirePersonMessage(t, n.PersonMessage, n.Links)
	return n
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
	describe := describeUseCase(cmds, &fakeCatalog{notGranted: 12})
	granted, err := describe.DescribeOverview(context.Background())
	require.NoError(t, err)
	messages["not granted"] = granted.PersonMessage
	messages["describe not found"] = describe.DescribeNotFoundSteps(guidance.NewSteps(), guidance.Failure{Tool: guidance.ToolDescribe})
	rls := &Service{deps: Deps{Core: CoreDeps{Commands: cmds, Log: slog.New(slog.DiscardHandler)}}}
	rls.wire()
	w, err := rls.write.rlsWarning("public." + strings.Repeat("t", 60))
	require.NoError(t, err)
	messages["rls warning"] = w.PersonMessage

	for name, m := range messages {
		require.NoError(t, guidance.CheckPersonMessage(m), "%s: %s", name, m)
		require.NotContains(t, m, long, name)
		require.NotContains(t, m, "basalt ", "%s: the person runs no command", name)
	}
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
