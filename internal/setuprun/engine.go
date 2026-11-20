package setuprun

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// EngineState is what the database records about the code's engine and
// its address (CONTRACT.md, Setup from your laptop, "The engine key and
// address"): read before the summary, with the admin connection.
type EngineState struct {
	// Key is the code's engine key (SPKI DER), nil when the code has none.
	Key []byte
	ID  string
	// Recorded is the database's row for this engine, nil when none.
	Recorded *guard.RecordedEngine
	// SameAddress are the other engines not revoked at the address given:
	// one revoke question each.
	SameAddress []guard.RecordedEngine
	// LastRevoked is the most recently revoked engine, nil when none.
	LastRevoked *guard.RecordedEngine
}

// readEngine reads the engines the database records when the code carries
// one, and refuses a revoked engine (step 4, ENGINE_REVOKED). A guard
// without the engines table records none yet: this setup's migrations add
// it.
func (s *Setup) readEngine(ctx context.Context, q guard.Querier) (EngineState, error) {
	if s.P.Engine == nil {
		return EngineState{}, nil
	}
	key, err := s.P.Engine.Key()
	if err != nil {
		return EngineState{}, err
	}
	st := EngineState{Key: key, ID: channel.EngineIDOf(key)}
	engines, err := guard.Engines(ctx, q, true)
	if isUndefinedTable(err) {
		return st, nil
	}
	if err != nil {
		return EngineState{}, err
	}
	for i := range engines {
		e := engines[i]
		switch {
		case e.ID == st.ID:
			st.Recorded = &e
		case e.RevokedAt != nil:
		case s.EngineURL != "" && e.URL != nil && *e.URL == s.EngineURL:
			st.SameAddress = append(st.SameAddress, e)
		}
		if e.RevokedAt != nil && (st.LastRevoked == nil || e.RevokedAt.After(*st.LastRevoked.RevokedAt)) {
			st.LastRevoked = &e
		}
	}
	if r := st.Recorded; r != nil && r.RevokedAt != nil {
		return EngineState{}, refuse(CodeEngineRevoked, fmt.Sprintf("ENGINE_REVOKED: engine %s was revoked in this database on %s. A revoked engine is never recorded again: "+
			"ask %s to run basalt engine rotate-key and make a new code", channel.FingerprintOf(st.ID), UTCMinute(*r.RevokedAt), AgentWord(s.P)))
	}
	return st, nil
}

// engineToRecord is whether the code's engine needs writing: not recorded,
// or recorded with another address than the one given.
func (p *Prepared) engineToRecord() bool {
	if p.Engine.Key == nil {
		return false
	}
	r := p.Engine.Recorded
	if r == nil {
		return true
	}
	return p.EngineURL != "" && (r.URL == nil || *r.URL != p.EngineURL)
}

// EngineLines are the engine lines of the summary (step 5), none when the
// code carries no engine key.
func (p *Prepared) EngineLines() []string {
	if p.Engine.Key == nil {
		return nil
	}
	agent := AgentWord(p.P)
	line := fmt.Sprintf("This records engine %s for %s.", channel.FingerprintOf(p.Engine.ID), agent)
	r := p.Engine.Recorded
	switch {
	case p.EngineURL != "" && r != nil && r.URL != nil && *r.URL != p.EngineURL:
		line += fmt.Sprintf(" Its address: %s (now %s).", p.EngineURL, *r.URL)
	case p.EngineURL != "":
		line += fmt.Sprintf(" Its address: %s.", p.EngineURL)
	case r != nil && r.URL != nil:
		line += fmt.Sprintf(" Its address stays %s.", *r.URL)
	}
	out := []string{line, fmt.Sprintf("Check that %s's basalt status shows the same engine fingerprint; your devices will pin this one.", agent)}
	if v := p.Engine.LastRevoked; v != nil {
		out = append(out, fmt.Sprintf("This database revoked engine %s on %s. Recording a new engine trusts the agent's server again: "+
			"do it only if you rebuilt or replaced that server.", channel.FingerprintOf(v.ID), UTCMinute(*v.RevokedAt)))
	}
	return out
}

// RevokeQuestion asks whether to revoke another engine at the same
// address.
func RevokeQuestion(e guard.RecordedEngine) string {
	return fmt.Sprintf("Engine %s is also recorded at %s (since %s). Revoke it?", channel.FingerprintOf(e.ID), *e.URL, UTCMinute(e.RecordedAt))
}

// checkRevoke refuses an engine to revoke that p did not ask about.
func (p *Prepared) checkRevoke(revoke []string) error {
	for _, id := range revoke {
		if !slices.ContainsFunc(p.Engine.SameAddress, func(e guard.RecordedEngine) bool { return e.ID == id }) {
			return refuse(CodeAnswersInvalid, fmt.Sprintf("the answers revoke engine %s, which this setup does not ask about; check the setup again", printableLabel(id)))
		}
	}
	return nil
}

// engineStatements are record_engine, and revoke_engine for each engine
// the person chose, in the setup's transaction before record_setup (step
// 6).
func (p *Prepared) engineStatements(revoke []string) []guard.Statement {
	if p.Engine.Key == nil {
		return nil
	}
	var url *string
	if p.EngineURL != "" {
		url = &p.EngineURL
	}
	out := []guard.Statement{guard.RecordEngineStatement(p.Engine.Key, url)}
	var done []string
	for _, id := range revoke {
		if slices.Contains(done, id) {
			continue
		}
		done = append(done, id)
		out = append(out, guard.RevokeEngineStatement(id))
	}
	return out
}

// UTCMinute is a time as the setup's messages print it.
func UTCMinute(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
