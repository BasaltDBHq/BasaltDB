package main

import (
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// upgradeLinePrefix starts the summary line of an UPGRADE code, replaced by
// "No guard change." when the code only records the engine.
const upgradeLinePrefix = "This upgrades Basalt's guard"

// pinAddURL is the portal page where each device pins the engine
// (CONTRACT.md, Direct transport).
const pinAddURL = "https://portal.basaltvault.app/engines/add"

// engineState is what the database records about the code's engine and its
// address (CONTRACT.md, Setup from your laptop, "The engine key and
// address"): read before the summary, with the admin connection.
type engineState struct {
	// key is the code's engine key (SPKI DER), nil when the code has none.
	key []byte
	id  string
	// recorded is the database's row for this engine, nil when none.
	recorded *guard.RecordedEngine
	// sameAddress are the other engines not revoked at the address given.
	sameAddress []guard.RecordedEngine
	// lastRevoked is the most recently revoked engine, nil when none.
	lastRevoked *guard.RecordedEngine
}

// readEngine reads the engines the database records when the code carries
// one, and refuses a revoked engine (step 4, ENGINE_REVOKED). A guard
// without version 33 records none yet: this setup's migrations add it.
func (l *laptopSetup) readEngine() error {
	if l.p.Engine == nil {
		return nil
	}
	key, err := l.p.Engine.Key()
	if err != nil {
		return err
	}
	l.engine = engineState{key: key, id: channel.EngineIDOf(key)}
	engines, err := guard.Engines(l.c.ctx, l.conn, true)
	if isUndefinedTable(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for i := range engines {
		e := engines[i]
		switch {
		case e.ID == l.engine.id:
			l.engine.recorded = &e
		case e.RevokedAt != nil:
		case l.f.engineURL != "" && e.URL != nil && *e.URL == l.f.engineURL:
			l.engine.sameAddress = append(l.engine.sameAddress, e)
		}
		if e.RevokedAt != nil && (l.engine.lastRevoked == nil || e.RevokedAt.After(*l.engine.lastRevoked.RevokedAt)) {
			l.engine.lastRevoked = &e
		}
	}
	if r := l.engine.recorded; r != nil && r.RevokedAt != nil {
		return fmt.Errorf("ENGINE_REVOKED: engine %s was revoked in this database on %s. A revoked engine is never recorded again: "+
			"ask %s to run basalt engine rotate-key and make a new code", channel.FingerprintOf(l.engine.id), utcMinute(*r.RevokedAt), agentWord(l.p))
	}
	return nil
}

// engineToRecord is whether the code's engine needs writing: not recorded,
// or recorded with another address than --engine-url.
func (l *laptopSetup) engineToRecord() bool {
	if l.engine.key == nil {
		return false
	}
	r := l.engine.recorded
	if r == nil {
		return true
	}
	return l.f.engineURL != "" && (r.URL == nil || *r.URL != l.f.engineURL)
}

// engineSummary prints the engine lines of the summary (step 5) and asks,
// for each other engine at the address given, whether to revoke it.
func (l *laptopSetup) engineSummary() error {
	if l.engine.key == nil {
		return nil
	}
	c := l.c
	line := fmt.Sprintf("This records engine %s for %s.", channel.FingerprintOf(l.engine.id), agentWord(l.p))
	r := l.engine.recorded
	switch {
	case l.f.engineURL != "" && r != nil && r.URL != nil && *r.URL != l.f.engineURL:
		line += fmt.Sprintf(" Its address: %s (now %s).", l.f.engineURL, *r.URL)
	case l.f.engineURL != "":
		line += fmt.Sprintf(" Its address: %s.", l.f.engineURL)
	case r != nil && r.URL != nil:
		line += fmt.Sprintf(" Its address stays %s.", *r.URL)
	}
	fprintSafef(c.stdout, "%s\n", line)
	fmt.Fprintf(c.stdout, "Check that %s's basalt status shows the same engine fingerprint; your devices will pin this one.\n", agentWord(l.p))
	if v := l.engine.lastRevoked; v != nil {
		fmt.Fprintf(c.stdout, "This database revoked engine %s on %s. Recording a new engine trusts the agent's server again: "+
			"do it only if you rebuilt or replaced that server.\n", channel.FingerprintOf(v.ID), utcMinute(*v.RevokedAt))
	}
	for _, e := range l.engine.sameAddress {
		revoke, err := l.askRevoke(e)
		if err != nil {
			return err
		}
		if revoke {
			l.revoke = append(l.revoke, e.ID)
		}
	}
	return nil
}

// askRevoke asks whether to revoke another engine at the same address.
// With --yes or --dry-run none is revoked, and init says so.
func (l *laptopSetup) askRevoke(e guard.RecordedEngine) (bool, error) {
	c := l.c
	q := fmt.Sprintf("Engine %s is also recorded at %s (since %s). Revoke it?", channel.FingerprintOf(e.ID), *e.URL, utcMinute(e.RecordedAt))
	if l.f.yes || l.f.dryRun {
		fmt.Fprintf(c.stderr, "basalt: %s Not revoked (--yes or --dry-run); basalt engine revoke %s revokes it.\n", q, e.ID)
		return false, nil
	}
	return c.confirm(q)
}

// engineStatements are record_engine, and revoke_engine for each engine
// the person chose, in the setup's transaction before record_setup (step 6).
func (l *laptopSetup) engineStatements() []guard.Statement {
	if l.engine.key == nil {
		return nil
	}
	var url *string
	if l.f.engineURL != "" {
		url = &l.f.engineURL
	}
	out := []guard.Statement{guard.RecordEngineStatement(l.engine.key, url)}
	for _, id := range l.revoke {
		out = append(out, guard.RevokeEngineStatement(id))
	}
	return out
}

// utcMinute is a time as the setup's messages print it.
func utcMinute(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
