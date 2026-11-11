package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

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
	got := plainText("Fix leads\nsee https://evil.example/x and\r\n\x1b[31mred\x07")
	require.Equal(t, "Fix leads see https evil.example/x and [31mred", got)
	require.NotRegexp(t, `https?://`, got)
	require.Equal(t, "short", shown("short", 10))
	require.Equal(t, "abcdefg...", shown("abcdefghijklmnop", 10))
}
