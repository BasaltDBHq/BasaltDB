package setupcode

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ClockSkew is the clock difference tolerated between the code-maker and
// the person's computer (RI-13). Expiry itself has no skew.
const ClockSkew = 5 * time.Minute

// timeLayout is how refusals show a time: 2026-11-12 07:02 UTC.
const timeLayout = "2006-01-02 15:04 UTC"

// MinGuardVersion is the first guard version that records a setup
// (basalt_meta.setups and record_setup). A code whose guard.to is older
// cannot be applied: its transaction would end in a function the database
// does not have. Every guard version records setups.
const MinGuardVersion = 1

// CheckLocal applies the person's computer's checks to a decoded code, in
// the contract's order: EXPIRED (now at or past expiresAt),
// SETUP_ID_IN_FUTURE (the setupId's time more than ClockSkew ahead),
// EXPIRY_TOO_FAR (expiresAt more than Lifetime and ClockSkew ahead), then
// BINARY_TOO_OLD (guard.to newer than binaryGuardVersion), then
// GUARD_TOO_OLD (guard.to older than MinGuardVersion). The code-maker writes
// both times, so the clock decides, not the code.
func CheckLocal(p Payload, now time.Time, binaryGuardVersion int) error {
	expires, err := p.ExpiresTime()
	if err != nil {
		return err
	}
	created, err := p.CreatedAt()
	if err != nil {
		return err
	}
	agent := p.agentWord()
	switch {
	case !now.Before(expires):
		return refuseWith(RefusalExpired, "This setup code expired on "+expires.UTC().Format(timeLayout)+". Ask "+agent+" for a new one.")
	case created.After(now.Add(ClockSkew)):
		return refuseWith(RefusalSetupIDInFuture, futureMessage(agent))
	case expires.After(now.Add(Lifetime + ClockSkew)):
		return refuseWith(RefusalExpiryTooFar, futureMessage(agent))
	case p.Guard.To > binaryGuardVersion:
		return refuseWith(RefusalBinaryTooOld, "Update basalt on this computer to at least "+p.Build+".")
	case p.Guard.To < MinGuardVersion:
		return refuseWith(RefusalGuardTooOld, fmt.Sprintf("This setup code is for guard version %d, but setup codes need guard version %d or later. "+
			"Ask %s for a new code made with an up-to-date basalt.", p.Guard.To, MinGuardVersion, agent))
	}
	return nil
}

// CheckNotConnectOnly refuses a connect-only code (no target) on the laptop
// path, basalt init --setup-code, before the clock checks: only the connect
// page runs it (CONNECT_ONLY).
func CheckNotConnectOnly(p Payload) error {
	if !p.ConnectOnly() {
		return nil
	}
	return refuseWith(RefusalConnectOnly, "This setup code is for the connect page: open the link "+p.agentWord()+
		" sent, or ask it for a code for this command (basalt init --remote --database-url <the database, without password>).")
}

func futureMessage(agent string) string {
	return "This setup code claims a time in the future. Check this computer's clock, or ask " + agent + " for a new code."
}

// agentWord names the agent in messages: its name, or "your agent" for an
// UPGRADE code, which has none.
func (p Payload) agentWord() string {
	if p.Agent == nil {
		return "your agent"
	}
	return p.Agent.Name
}

// Database is what the person's computer read with the admin connection
// string.
type Database struct {
	// Prefix of the installed basalt_meta (its owner role is
	// <prefix>_guard); empty when none is installed.
	Prefix string
	// Roles that exist among those the code names.
	Roles []string
	// Setups recorded in basalt_meta.setups.
	Setups []RecordedSetup
}

// RecordedSetup is one row of basalt_meta.setups.
type RecordedSetup struct {
	SetupID   string
	AgentRole string
	UsedAt    time.Time
}

// CheckDatabase applies the checks against the database's state, in the
// contract's order: PREFIX_MISMATCH, USED, SUPERSEDED (a newer setup of the
// same agent ran; UUIDv7 ids are time-ordered), ROLE_EXISTS (an INSTALL
// code never touches an existing role), ROLE_MISSING (an AGENT code needs
// the role). record_setup and CREATE ROLE enforce the same in Postgres.
func CheckDatabase(p Payload, db Database) error {
	if db.Prefix != "" && db.Prefix != p.Prefix {
		return refuseWith(RefusalPrefixMismatch, "This setup code is for prefix "+p.Prefix+", but this database's Basalt uses "+db.Prefix+".")
	}
	agent, role := p.agentWord(), p.Role()
	for _, s := range db.Setups {
		if s.SetupID == p.SetupID {
			return refuseWith(RefusalUsed, "This setup code was already used on "+s.UsedAt.UTC().Format(timeLayout)+". Ask "+agent+" for a new one.")
		}
	}
	if role != "" {
		if err := checkSuperseded(p, db.Setups, role); err != nil {
			return err
		}
	}
	exists := role != "" && slices.Contains(db.Roles, role)
	switch {
	case p.Kind == KindInstall && exists:
		return refuseWith(RefusalRoleExists, role+" already exists. This code would replace its password: ask "+agent+
			" for a new code, or run basalt init --remote --new-code for that agent if it is yours.")
	case p.Kind == KindAgent && !exists && !p.ConnectOnly():
		// A connect-only recovery code whose role does not exist runs as
		// an INSTALL instead (CONTRACT.md, Connect-only setup codes).
		return refuseWith(RefusalRoleMissing, role+" does not exist. Ask "+agent+" for a new code.")
	}
	return nil
}

func checkSuperseded(p Payload, setups []RecordedSetup, role string) error {
	id, err := uuid.Parse(p.SetupID)
	if err != nil {
		return invalid("setupId is not a UUIDv7")
	}
	for _, s := range setups {
		// setups.setup_id is a uuid column: an id that does not parse cannot
		// come from Postgres and is not newer than anything.
		other, err := uuid.Parse(s.SetupID)
		if s.AgentRole != role || err != nil || bytes.Compare(other[:], id[:]) <= 0 {
			continue
		}
		return refuseWith(RefusalSuperseded, "A newer setup for "+p.agentWord()+" already ran on "+s.UsedAt.UTC().Format(timeLayout)+
			". Ask "+p.agentWord()+" for a new code.")
	}
	return nil
}
