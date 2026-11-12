package agent

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp/mcptest"
)

// requirePersonMessage is the engine's check of CONTRACT.md, Links in
// personMessage, for every personMessage the engine builds.
func requirePersonMessage(t *testing.T, message string, links []mcp.Link) {
	t.Helper()
	mcptest.Require(t, message, links)
}

func TestMessageLimitMatchesTheContract(t *testing.T) {
	t.Parallel()
	require.Equal(t, MaxPersonMessageLength, mcptest.PersonMessageLimit)
}

func TestMessageBuilder(t *testing.T) {
	t.Parallel()
	const first, second = "http://localhost:8787/approvals/1#s=a", "http://localhost:8787/reverts/2#s=b"

	msg, links := newMessage().
		Text("Held for you.").Text("Approve here:").
		Link("Approve the held write", first).
		Text("Or run: basalt approve.").Text("Expires soon.").
		Link("Review and sign the revert", second).
		Build()

	require.Equal(t, "Held for you.\nApprove here:\n\n"+first+"\n\nOr run: basalt approve.\nExpires soon.\n\n"+second, msg)
	require.Equal(t, []mcp.Link{{Label: "Approve the held write", URL: first}, {Label: "Review and sign the revert", URL: second}}, links)
	requirePersonMessage(t, msg, links)

	plain, none := newMessage().Text("No link.").Build()
	require.Equal(t, "No link.", plain)
	require.Nil(t, none, "links are present exactly when the message holds a URL")
}

func TestPlainTextKeepsAgentTextOutOfTheURLRule(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Fix leads see https evil.example/x and [31mred", plainText("Fix leads\nsee https://evil.example/x and\r\n\x1b[31mred\x07"))
	for name, probe := range map[string]string{
		"underscore before scheme": "_https://evil.example/x",
		"letter before scheme":     "xhttps://evil.example/x",
		"www":                      "www.evil.example/x",
		"full-width colon":         "https：//evil.example/x",
		"full-width everything":    "https：／／evil.example",
		"zero-width space":         "ht\u200btps://evil.example/x",
		"soft hyphen":              "ht\u00adtps://evil.example/x",
		"control inside":           "ht\x00tps://evil.example/x",
		"no-break space":           "see https://evil.example/x",
		"next line":                "a\u0085https://evil.example/x",
		"line separator":           "a https://evil.example/x",
		"vertical tab":             "a\vhttps://evil.example/x",
		"nested":                   "ht:///tps://evil.example",
		"long fragment 2":          "#2.abcdef",
		"long fragment 1":          "see #1.abcdef",
		"short fragment":           "x#s=abcdefghijklmnopqrstuv",
		"split fragment":           "#\u200b2.abc",
	} {
		got := plainText(probe)
		require.NotRegexp(t, `(?i)//|www\.|#1\.|#2\.|#s=|\p{Cf}|\p{Cc}`, got, name)
		require.Empty(t, urlPattern.FindString(got), name)
	}
	require.Equal(t, "short", shown("short", 10))
	require.Equal(t, "abcdefg...", shown("abcdefghijklmnop", 10))
}

var urlPattern = regexp.MustCompile(`https?://\S+`)

// Every personMessage of a revert's states obeys the contract, without a
// database.
func TestRevertStateMessagesObeyTheContract(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for _, origin := range []string{localPages, ""} {
		s := noticeService(origin, links.DefaultBudget)
		for _, status := range []string{ledger.RevertApplied, ledger.RevertApplying, ledger.RevertExpired, ledger.RevertPending} {
			for _, batched := range []bool{false, true} {
				r := revertOf(t, "Undo", revertLines(3), batched)
				r.Status, r.ApplyBy = status, &at
				out, err := s.revertState(context.Background(), r)
				require.NoError(t, err)
				requirePersonMessage(t, out.PersonMessage, out.Links)
			}
		}
	}
}
