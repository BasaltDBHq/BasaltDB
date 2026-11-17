package ledger_test

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// personMessageLimit is the status tool's personMessage limit
// (agent.MaxPersonMessageLength).
const personMessageLimit = 500

var (
	noticeAt   = time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	noticeHash = bytes.Repeat([]byte{0xab}, 32)
	hashHex    = strings.Repeat("ab", 32)
	// testInstall is the install the notices are about.
	testInstall = uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2b")
)

func report(agent string, seq int64, more int) guard.ReinstallReport {
	return guard.ReinstallReport{Agent: agent, At: noticeAt, PinnedSeq: seq, PinnedHash: noticeHash, More: more}
}

func TestReinstallNoticeWording(t *testing.T) {
	t.Parallel()
	installed := noticeAt.Add(-time.Hour)
	r := guard.Reinstall{
		Install: testInstall, InstalledAt: &installed, InstalledBy: "postgres", VaultUser: "alice@example.com",
		Reports:    []guard.ReinstallReport{report("basalt_agent_bot", 42, 0), report("basalt_agent_two", 40, 2), report("basalt_agent_three", 41, 0)},
		MoreAgents: 4,
	}
	require.Equal(t, []string{
		"This database's ledger was reinstalled on 2026-11-14T08:30:00Z by postgres (via Vault: alice@example.com). " +
			"Previous ledger ended at entry 42 (hash " + hashHex + "), as reported with the credential of basalt_agent_bot. " +
			"If nobody on your team reinstalled Basalt, treat this as tampering.",
		"Also reported with the credential of basalt_agent_two: entry 40 (hash " + hashHex + "), and 2 more reports.",
		"Also reported with the credential of basalt_agent_three: entry 41 (hash " + hashHex + ").",
		"and 4 more agents",
	}, ledger.ReinstallNotice(r))

	r.VaultUser = ""
	require.Contains(t, ledger.ReinstallNotice(r)[0], " by postgres. Previous ledger", "no Vault user, no via")
}

func TestReinstallNoticeWithoutAnInstallRecord(t *testing.T) {
	t.Parallel()
	r := guard.Reinstall{Install: testInstall, Reports: []guard.ReinstallReport{report("basalt_agent_bot", 7, 0)}}
	require.Equal(t, []string{
		"This database's ledger was recreated or restored outside basalt init (no install record), first reported 2026-11-14T09:30:00Z. " +
			"Previous ledger ended at entry 7 (hash " + hashHex + "), as reported with the credential of basalt_agent_bot. " +
			"If nobody on your team reinstalled Basalt, treat this as tampering.",
	}, ledger.ReinstallNotice(r))
}

func TestReinstallNoticesCountEarlierOnes(t *testing.T) {
	t.Parallel()
	one := guard.Reinstall{Install: testInstall, Reports: []guard.ReinstallReport{report("bot", 7, 0)}}
	lines := ledger.ReinstallNotices(guard.Reinstalls{List: []guard.Reinstall{one, one, one}, Earlier: 2})
	require.Len(t, lines, 4)
	require.Equal(t, "and 2 earlier reinstalls", lines[3])
	require.Empty(t, ledger.ReinstallNotices(guard.Reinstalls{}))
}

func TestReinstallPersonMessage(t *testing.T) {
	t.Parallel()
	_, ok := ledger.ReinstallPersonMessage(guard.Reinstalls{}, personMessageLimit)
	require.False(t, ok)

	installed := noticeAt
	r := guard.Reinstall{
		Install: testInstall, InstalledAt: &installed, InstalledBy: "postgres", VaultUser: strings.Repeat("v", 100),
		Reports: []guard.ReinstallReport{report("bot", 7, 0), report("other", 8, 0)},
	}
	msg, ok := ledger.ReinstallPersonMessage(guard.Reinstalls{List: []guard.Reinstall{r}}, personMessageLimit)
	require.True(t, ok)
	require.Equal(t, ledger.ReinstallNotice(withVaultUser(r, strings.Repeat("v", ledger.VaultUserCut)))[0]+
		"\nRun basalt log to see every report.", msg, "the first line only, the Vault user cut")
	require.NotContains(t, msg, "other")

	// Every field at its longest still fits.
	r.InstalledBy, r.Reports[0].Agent, r.Reports[0].PinnedSeq = strings.Repeat("a", 63), strings.Repeat("b", 63), 1<<62
	msg, ok = ledger.ReinstallPersonMessage(guard.Reinstalls{List: []guard.Reinstall{r}}, personMessageLimit)
	require.True(t, ok)
	require.LessOrEqual(t, utf8.RuneCountInString(msg), personMessageLimit)
	require.True(t, strings.HasSuffix(msg, "Run basalt log to see every report."))
}

func withVaultUser(r guard.Reinstall, v string) guard.Reinstall {
	r.VaultUser = v
	return r
}

// A name read from the database cannot put control characters on the
// person's terminal.
func TestReinstallNoticeReplacesControlCharacters(t *testing.T) {
	t.Parallel()
	r := guard.Reinstall{Install: testInstall, Reports: []guard.ReinstallReport{report("bot\x1b[2J\nfake", 7, 0)}}
	line := ledger.ReinstallNotice(r)[0]
	require.NotContains(t, line, "\x1b")
	require.NotContains(t, line, "\n")
}
