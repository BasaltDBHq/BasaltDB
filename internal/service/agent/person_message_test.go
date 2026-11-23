package agent

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
)

// requirePersonMessage is the engine's check of CONTRACT.md, Links in
// personMessage, for every personMessage the engine builds.
func requirePersonMessage(t *testing.T, message string, links []toolresult.Link) {
	t.Helper()
	mcptest.Require(t, message, links)
	require.Empty(t, removedCommand.FindString(message), "a personMessage names no removed command (CONTRACT.md, Next steps): %q", message)
}

// removedCommand is a basalt command or init flag the person no longer runs
// ([Removed](contract/cli.md#removed)). --json and --forget count only on
// basalt init: the plugin steps, which the plugin epic replaces, still take
// --json.
var removedCommand = regexp.MustCompile(`basalt (approve|revert|upgrade|passkey|trust|access|status|portal|crash|service|log|classify|uninstall|tunnel)\b|--setup-code|--add-passkey|--rotate-password|--agent-rls|--new-code|rotate-key|basalt init\b[^\n]*?--(forget|json)`)

// TestRemovedCommandCatchesEveryRemovedForm: the check the catalog tests
// run on every step and personMessage catches each removed command and
// init flag, and lets the agent's basalt init and plain words through.
func TestRemovedCommandCatchesEveryRemovedForm(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"Run: basalt upgrade --agent bot", "basalt approve --open x", "basalt revert --run x --open", "basalt passkey list",
		"basalt trust pin --host h", "basalt access --agent bot", "basalt portal verify", "basalt init --setup-code c",
		"basalt init --agent bot --add-passkey", "basalt init --remote --new-code", "basalt init --remote --forget",
		"basalt init --remote --json", "basalt log", "basalt engine rotate-key",
	} {
		require.NotEmpty(t, removedCommand.FindString(bad), bad)
	}
	for _, ok := range []string{
		"basalt init --agent bot", "basalt init --agent bot --remote", "sudo systemctl start basalt-engine.service",
		"Basalt's status reports KEY_ERROR", "Tell the agent when it is done.", "the revert page",
	} {
		require.Empty(t, removedCommand.FindString(ok), ok)
	}
}

func TestMessageLimitMatchesTheContract(t *testing.T) {
	t.Parallel()
	require.Equal(t, guidance.MaxPersonMessageLength, mcptest.PersonMessageLimit)
}

func TestMessageBuilder(t *testing.T) {
	t.Parallel()
	const first, second = "http://localhost:8787/approvals/1#s=a", "http://localhost:8787/reverts/2#s=b"

	msg, links := guidance.NewMessage().
		Text("Held for you.").Text("Approve here:").
		Link("Approve the held write", first).
		Text("Approve with your passkey.").Text("Expires soon.").
		Link("Review and sign the revert", second).
		Build()

	require.Equal(t, "Held for you.\nApprove here:\n\n"+first+"\n\nApprove with your passkey.\nExpires soon.\n\n"+second, msg)
	require.Equal(t, []toolresult.Link{{Label: "Approve the held write", URL: first}, {Label: "Review and sign the revert", URL: second}}, links)
	requirePersonMessage(t, msg, links)

	plain, none := guidance.NewMessage().Text("No link.").Build()
	require.Equal(t, "No link.", plain)
	require.Nil(t, none, "links are present exactly when the message holds a URL")
}

func TestPlainTextKeepsAgentTextOutOfTheURLRule(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Fix leads see https evil·example/x and [31mred", guidance.PlainText("Fix leads\nsee https://evil.example/x and\r\n\x1b[31mred\x07"))
	for name, probe := range map[string]string{
		"bare dotted host":         "see portal.basaltvault.app.evil.io/x now",
		"bare host":                "evil.io",
		"backslash scheme":         `https:\\evil`,
		"mixed slashes":            `https:/\evil`,
		"division slash":           "https:\u2215\u2215evil",
		"fraction slash":           "https:\u2044\u2044evil",
		"big solidus":              "https:\u29f8\u29f8evil",
		"ideographic full stop":    "evil\u3002io",
		"markdown link":            "[the page](https:evil)",
		"ip with port":             "10.0.0.1:8080/approve",
		"scheme and ip":            "http:1.2.3.4",
		"localhost":                "localhost:8080/x",
		"underscore before scheme": "_https://evil.example/x",
		"letter before scheme":     "xhttps://evil.example/x",
		"www":                      "www.evil.example/x",
		"full-width colon":         "https：//evil.example/x",
		"full-width everything":    "https：／／evil.example",
		"zero-width space":         "ht\u200btps://evil.example/x",
		"soft hyphen":              "ht\u00adtps://evil.example/x",
		"control inside":           "ht\x00tps://evil.example/x",
		"no-break space":           "see\u00a0https://evil.example/x",
		"next line":                "a\u0085https://evil.example/x",
		"line separator":           "a\u2028https://evil.example/x",
		"vertical tab":             "a\vhttps://evil.example/x",
		"nested":                   "ht:///tps://evil.example",
		"long fragment 2":          "#2.abcdef",
		"long fragment 1":          "see #1.abcdef",
		"short fragment":           "x#s=abcdefghijklmnopqrstuv",
		"split fragment":           "#\u200b2.abc",
	} {
		got := guidance.PlainText(probe)
		require.NotRegexp(t, `(?i)//|\\\\|www\.|#1\.|#2\.|#s=|\p{Cf}|\p{Cc}|[\x{2215}\x{2044}\x{29f8}]|\]\(`, got, name)
		require.NotRegexp(t, `[\p{L}\p{N}_-]\.\p{L}`, got, name, "no bare host")
		require.NotRegexp(t, `\d+\.\d+\.\d+\.\d+|\S:\d+/|\p{L}:\d`, got, name, "no address or port")
		require.Empty(t, urlPattern.FindString(got), name)
	}
	// Each form, neutralized and still readable.
	for probe, want := range map[string]string{
		"see portal.basaltvault.app.evil.io/x now": "see portal·basaltvault·app·evil·io/x now",
		`https:\\evil.io`:                          "https evil·io",
		"https:\u2215\u2215evil.io\u2215x":         "https evil·io/x",
		"https:\u2044\u2044evil":                   "https evil",
		"https:\u29f8\u29f8evil":                   "https evil",
		"[the page](evil.io)":                      "[the page] (evil·io)",
		"Update 3 rows in public.leads":            "Update 3 rows in public·leads",
		"raise prices by 1.5 percent":              "raise prices by 1.5 percent",
		"10.0.0.1:8080/approve":                    "10·0·0·1 :8080/approve",
		"http:1.2.3.4":                             "http :1·2·3·4",
		"see localhost:8080/x":                     "see localhost :8080/x",
		"localhost:8080":                           "localhost :8080",
		"meet at 10:30 today":                      "meet at 10:30 today",
	} {
		require.Equal(t, want, guidance.PlainText(probe), probe)
	}
	require.Equal(t, "short", guidance.Shown("short", 10))
	require.Equal(t, "abcdefg...", guidance.Shown("abcdefghijklmnop", 10))
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

// The person message states the agent's name and the limit the role SQL
// sets, word for word as CONTRACT.md has it.
func TestTooManyConnectionsMessageWords(t *testing.T) {
	t.Parallel()
	cmds, err := NewCommands("lead_bot", "", "linux", testManager())
	require.NoError(t, err)
	require.Equal(t, "The agent lead_bot has used all 8 database connections Basalt allows it. "+
		"Another engine for the same agent may be running, or a stopped engine left sessions open. "+
		"Stop any second engine; stale sessions close on their own within a few minutes.",
		tooManyConnectionsMessage(cmds))
	require.Equal(t, 8, setupcode.AgentConnectionLimit, "the message above and the role SQL state the same limit")
}
