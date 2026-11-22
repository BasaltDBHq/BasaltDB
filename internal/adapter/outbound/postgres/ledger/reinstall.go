package ledger

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// Reinstalls on the record (CONTRACT.md, "Version 36: reinstalls on the
// record"): what a witness does with a pin of another install, and the
// notice the status tool shows.

// PinFate is what became of a pin of another install.
type PinFate int

const (
	// PinKept: the pin could not be reported (the database is down, or the
	// guard is older than version 36). It is checked as before, so the
	// reinstall shows as a broken chain.
	PinKept PinFate = iota
	// PinMoved: the pinned entry is still on the current chain and the whole
	// chain verifies: the same ledger under a new oid (a pg_dump and
	// pg_restore). Nothing is recorded; the pin moves to the new install.
	PinMoved
	// PinSetAside: the pin was reported with record_pin_set_aside (now or
	// earlier) and is set aside; the new chain is checked from its start.
	PinSetAside
)

// SettledPin is the result of SettlePin.
type SettledPin struct {
	Fate PinFate
	// Head is the head verified from the pin when it moved, to pin next.
	Head guard.ChainHead
	// RecordErr is why the pin could not be reported (PinKept).
	RecordErr error
}

// SettlePin runs steps 1 to 3 of "Who sets a pin aside" for pin, verified
// on pinInstall, another install than the current one. It fails only when
// the check of step 1 cannot run (the database is down); a report that
// cannot be made is PinKept, never a set-aside.
func SettlePin(ctx context.Context, q guard.Querier, pin guard.ChainHead, pinInstall uuid.UUID) (SettledPin, error) {
	head, moved, err := pinMoves(ctx, q, pin)
	if err != nil {
		return SettledPin{}, err
	}
	if moved {
		return SettledPin{Fate: PinMoved, Head: head}, nil
	}
	// false (already recorded, e.g. when the pin file could not be written
	// after an earlier report) counts as recorded.
	if _, err := guard.RecordPinSetAside(ctx, q, pin, pinInstall); err != nil {
		return SettledPin{Fate: PinKept, RecordErr: err}, nil //nolint:nilerr // a report that fails keeps the pin, which then shows as a broken chain (step 3)
	}
	return SettledPin{Fate: PinSetAside}, nil
}

// pinMoves is step 1: the pin is still on the current chain (through the
// anchor only while it is the genesis), the chain verifies from it, and
// the full chain verifies. A guard without pin_on_chain (older than
// version 36) fails PinStillOnChain: the pin then goes to step 2, which
// fails the same way and keeps it.
func pinMoves(ctx context.Context, q guard.Querier, pin guard.ChainHead) (guard.ChainHead, bool, error) {
	still, err := guard.PinStillOnChain(ctx, q, pin)
	if err != nil || !still {
		return guard.ChainHead{}, false, nil //nolint:nilerr // an older guard or a failed check goes to step 2, which reports it
	}
	st, head, err := guard.VerifyChainFrom(ctx, q, pin)
	if err != nil || !st.Intact {
		return guard.ChainHead{}, false, err
	}
	full, err := guard.VerifyChain(ctx, q)
	if err != nil || !full.Intact {
		return guard.ChainHead{}, false, err
	}
	return head, true, nil
}

// The notice's wording (CONTRACT.md, Version 36, The notice).
const (
	noticeInstalled = "This database's ledger was reinstalled on %s by %s%s."
	noticeVia       = " (via Vault: %s)"
	noticeNoRecord  = "This database's ledger was recreated or restored outside basalt init (no install record), first reported %s."
	noticePrevious  = " Previous ledger ended at entry %d (hash %s), as reported with the credential of %s." +
		" If nobody on your team reinstalled Basalt, treat this as tampering."
	noticeAlso        = "Also reported with the credential of %s: entry %d (hash %s)%s."
	noticeMoreReports = ", and %d more reports"
	noticeMoreAgents  = "and %d more agents"
	noticeEarlier     = "and %d earlier reinstalls"
	noticeRunLog      = "Older reports stay in the ledger's install records."
)

// Cuts that keep the status personMessage within its limit.
const (
	// VaultUserCut is how many characters of the Vault user's name the
	// status personMessage keeps.
	VaultUserCut = 64
	// roleCut is how many characters of a role name the personMessage keeps
	// when the whole message would be over its limit: role names are up to
	// 63 bytes, and with every field at its longest the message would not
	// fit.
	roleCut = 32
)

// ReinstallNotices are every notice line for rs: each
// reinstall's notice, newest first, then "and N earlier reinstalls".
func ReinstallNotices(rs guard.Reinstalls) []string {
	var out []string
	for _, r := range rs.List {
		out = append(out, ReinstallNotice(r)...)
	}
	if rs.Earlier > 0 {
		out = append(out, fmt.Sprintf(noticeEarlier, rs.Earlier))
	}
	return out
}

// ReinstallNotice is one reinstall's notice: its first line, one line per
// other agent credential that reported it, then "and N more agents".
func ReinstallNotice(r guard.Reinstall) []string {
	if len(r.Reports) == 0 {
		return nil
	}
	out := []string{firstLine(r, r.VaultUser, r.InstalledBy, r.Reports[0].Agent)}
	for _, rep := range r.Reports[1:] {
		more := ""
		if rep.More > 0 {
			more = fmt.Sprintf(noticeMoreReports, rep.More)
		}
		out = append(out, fmt.Sprintf(noticeAlso, safe(rep.Agent), rep.PinnedSeq, hex.EncodeToString(rep.PinnedHash), more))
	}
	if r.MoreAgents > 0 {
		out = append(out, fmt.Sprintf(noticeMoreAgents, r.MoreAgents))
	}
	return out
}

// ReinstallPersonMessage is the status problem's personMessage: the newest
// reinstall's first notice line, then noticeRunLog, the Vault user cut to VaultUserCut characters, and the role
// names cut too when the message would be over limit characters. False
// when there is no reinstall.
func ReinstallPersonMessage(rs guard.Reinstalls, limit int) (string, bool) {
	if len(rs.List) == 0 || len(rs.List[0].Reports) == 0 {
		return "", false
	}
	r := rs.List[0]
	by, agent := r.InstalledBy, r.Reports[0].Agent
	vault := cut(r.VaultUser, VaultUserCut)
	msg := firstLine(r, vault, by, agent) + "\n" + noticeRunLog
	if utf8.RuneCountInString(msg) <= limit {
		return msg, true
	}
	msg = firstLine(r, vault, cut(by, roleCut), cut(agent, roleCut)) + "\n" + noticeRunLog
	return cut(msg, limit), true
}

// firstLine is the notice's first line with the given Vault user, installer
// and reporting agent.
func firstLine(r guard.Reinstall, vault, by, agent string) string {
	first := r.Reports[0]
	head := fmt.Sprintf(noticeNoRecord, r.FirstReportedAt().UTC().Format(time.RFC3339))
	if r.InstalledAt != nil {
		via := ""
		if vault != "" {
			via = fmt.Sprintf(noticeVia, safe(vault))
		}
		head = fmt.Sprintf(noticeInstalled, r.InstalledAt.UTC().Format(time.RFC3339), safe(by), via)
	}
	return head + fmt.Sprintf(noticePrevious, first.PinnedSeq, hex.EncodeToString(first.PinnedHash), safe(agent))
}

// cut keeps the first n characters of s.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// safe replaces control characters in a name read from the database, so a
// role or Vault user name cannot move the cursor or break a line.
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}
