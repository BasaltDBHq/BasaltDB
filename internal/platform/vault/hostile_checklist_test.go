package vault_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// hostileCheck is one item of the hostile-Vault checklist (CONTRACT.md,
// Vault channel: The Vault is untrusted) and the tests that cover it: Go
// test functions by file, and node tests by file and exact title (or, for
// the shared vectors, the vector case names in the file the test reads).
type hostileCheck struct {
	item    string
	goTests map[string][]string
	node    map[string][]string
	vectors map[string][]string
}

// hostileChecklist is every item, and the test that holds it. Removing or
// renaming one of these tests fails TestHostileChecklistIsCovered: move the
// coverage, then update this list.
var hostileChecklist = []hostileCheck{
	{
		item: "tampered, duplicated, replayed, reordered, reflected and cross-session frames are refused by the engine (FRAME_INVALID, no request run)",
		goTests: map[string][]string{
			"internal/platform/vault/hostile_session_test.go": {"TestHostileVaultFramesToTheEngine", "TestHostileVaultSplicesAFrameIntoAnotherSession"},
			"internal/platform/vault/session_test.go":         {"TestSessionRefusesBadFrames"},
		},
	},
	{
		item: "the same attacks on the engine's frames are refused by the page",
		goTests: map[string][]string{
			"internal/app/vault_portal_page_internal_test.go": {"TestPortalChannelClientRefusesAHostileVault"},
		},
		node:    map[string][]string{"web/lib/channel.test.mjs": {"frame: ${c.name}"}},
		vectors: map[string][]string{"api/mcp/vault/testdata/frame.json": {"reordered: the second frame first", "replayed: the first frame again", "reflected: the engine's frame sent back to it", "spliced: a frame from another session", "a tampered tag", "a truncated frame"}},
	},
	{
		item: "a wrong secret, an expired, revoked or unknown link get LINK_REFUSED alike, with nothing before it",
		goTests: map[string][]string{
			"internal/platform/vault/hostile_session_test.go": {"TestDeadLinksGetNothingButLinkRefused"},
			"internal/platform/vault/session_test.go":         {"TestSessionRefusesDeadTokensAlike", "TestRevokedLinkEndsItsSessions"},
			"internal/app/vault_session_internal_test.go":     {"TestVaultSessionDeadTokenTiming", "TestVaultSessionEndsWhenItsLinkIsRevoked"},
		},
	},
	{
		item:    "the page refuses message 2 signed by another key, with a bad AEAD tag, or from another engine key than the session showed",
		node:    map[string][]string{"web/lib/channel.test.mjs": {"handshake: ${c.name}", "a garbled message 2 closes with HANDSHAKE_FAILED and shows nothing"}, "web/lib/relay.test.mjs": {"a reopen that reaches another engine key is never used"}},
		vectors: map[string][]string{"api/mcp/vault/testdata/handshake.json": {"signed by another key", "a tampered ciphertext", "signed under the receipt context"}},
	},
	{
		item: "no route outside the pages API in a session: /healthz, link issuing, scripts, unknown methods, passkey and box-key registration, setups",
		goTests: map[string][]string{
			"internal/app/vault_session_internal_test.go": {"TestVaultSessionKeepsThePagesRules"},
			"internal/app/hostile_relay_internal_test.go": {"TestRelayChannelCannotSignWithoutThePerson"},
		},
	},
	{
		item: "size caps: message 1, frames, ROUTE and control messages, headers, a 16 KiB body (413), sessions per link and per engine, a session idle 5 minutes or open 30",
		goTests: map[string][]string{
			"internal/platform/vault/hostile_session_test.go": {"TestMessageOneOfAnotherLength"},
			"internal/platform/vault/session_test.go":         {"TestSessionOversizeFrames", "TestSessionLimits", "TestSessionAnswersRequests", "TestSessionTimeouts"},
			"internal/platform/vault/hostile_test.go":         {"TestRefusesAHostileVault", "TestSessionLimitAndHandshakeTimeout"},
			"internal/app/vault_session_internal_test.go":     {"TestVaultSessionKeepsThePagesRules"},
		},
	},
	{
		item:    "a revert's scope is not widened through the channel without the person's proof (the refused widen answers as on loopback and returns nothing of the widened scope)",
		goTests: map[string][]string{"internal/app/vault_rescope_internal_test.go": {"TestVaultSessionWidensARevert"}},
	},
	{
		item:    "forged SESSION_OPEN, OK, ERROR and SESSION_CLOSE do no harm",
		goTests: map[string][]string{"internal/platform/vault/vault_test.go": {"TestForgedControlMessagesAreHarmless"}},
	},
	{
		item: "without the person's passkey nothing is approved or applied through the channel; a signature for another item is refused by Postgres",
		goTests: map[string][]string{
			"internal/app/hostile_relay_internal_test.go": {"TestRelayChannelCannotSignWithoutThePerson"},
			"internal/app/vault_session_internal_test.go": {"TestVaultSessionApprovesAHeldWrite"},
		},
	},
	{
		item: "the page refuses a request whose rowsHash does not match, and shows nothing from an engine whose handshake failed",
		node: map[string][]string{
			"web/lib/relaypages.test.mjs": {"a request the engine altered is refused over the relay as on loopback, before anything is signed"},
			"web/lib/channel.test.mjs":    {"a garbled message 2 closes with HANDSHAKE_FAILED and shows nothing"},
		},
		goTests: map[string][]string{"internal/app/vault_portal_page_internal_test.go": {"TestPortalChannelClientRefusesAHostileVault"}},
	},
	{
		item:    "a real approval through a Vault that drops, delays or duplicates frames: applied once with the passkey, or a clean failure, never twice",
		goTests: map[string][]string{"internal/app/hostile_relay_internal_test.go": {"TestRelayApprovalThroughAHostileVault"}},
	},
}

// readRepo reads a file by its path from the repository root.
func readRepo(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(path)))
	require.NoError(t, err, path)
	return string(b)
}

// Every checklist item has its tests, and each named test is still there:
// a removed or renamed one fails here (make ci runs every package).
func TestHostileChecklistIsCovered(t *testing.T) {
	t.Parallel()
	for _, c := range hostileChecklist {
		require.Positive(t, len(c.goTests)+len(c.node), c.item)
		for file, names := range c.goTests {
			src := readRepo(t, file)
			for _, name := range names {
				require.Regexp(t, regexp.MustCompile(`(?m)^func `+regexp.QuoteMeta(name)+`\(t \*testing\.T\) \{$`), src, "%s: %s in %s", c.item, name, file)
			}
		}
		for file, titles := range c.node {
			src := readRepo(t, file)
			for _, title := range titles {
				quoted := `"` + title + `"`
				if strings.Contains(title, "${") {
					quoted = "`" + title + "`"
				}
				require.Contains(t, src, "test("+quoted, "%s: node test %q in %s", c.item, title, file)
			}
		}
		for file, names := range c.vectors {
			src := readRepo(t, file)
			for _, name := range names {
				require.Contains(t, src, `"name": "`+name+`"`, "%s: vector %q in %s", c.item, name, file)
			}
		}
	}
}
