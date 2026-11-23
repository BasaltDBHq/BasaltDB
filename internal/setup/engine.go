package setup

import (
	"context"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// EngineState is what the database records about the code's engine
// (CONTRACT.md, Setup from your laptop, "The engine key and address"): read
// before the summary, with the admin connection.
type EngineState struct {
	// Key is the code's engine key (SPKI DER), nil when the code has none.
	Key []byte
	ID  string
	// Recorded is the database's row for this engine, nil when none.
	Recorded *guardmodel.RecordedEngine
	// LastRevoked is the most recently revoked engine, nil when none.
	LastRevoked *guardmodel.RecordedEngine
}

// readEngine reads the engines the database records when the code carries
// one, and refuses a revoked engine (step 4, ENGINE_REVOKED). A guard
// without the engines table records none yet: this setup's migrations add
// it.
func (s *Setup) readEngine(ctx context.Context, q Querier) (EngineState, error) {
	if s.P.Engine == nil {
		return EngineState{}, nil
	}
	key, err := s.P.Engine.Key()
	if err != nil {
		return EngineState{}, err
	}
	st := EngineState{Key: key, ID: channel.EngineIDOf(key)}
	engines, err := s.be.Engines(ctx, q, true)
	if isUndefinedTable(err) {
		return st, nil
	}
	if err != nil {
		return EngineState{}, err
	}
	for i := range engines {
		e := engines[i]
		if e.ID == st.ID {
			st.Recorded = &e
		}
		if e.RevokedAt != nil && (st.LastRevoked == nil || e.RevokedAt.After(*st.LastRevoked.RevokedAt)) {
			st.LastRevoked = &e
		}
	}
	if r := st.Recorded; r != nil && r.RevokedAt != nil {
		return EngineState{}, refuse(CodeEngineRevoked, fmt.Sprintf("ENGINE_REVOKED: engine %s was revoked in this database on %s. A revoked engine is never recorded again: "+
			"ask %s to set the engine up again from the start and make a new code", channel.FingerprintOf(st.ID), UTCMinute(*r.RevokedAt), AgentWord(s.P)))
	}
	return st, nil
}

// engineToRecord is whether the code's engine needs writing: not recorded,
// or recorded with another address than the one given.
func (p *Prepared) engineToRecord() bool {
	return p.Engine.Key != nil && p.Engine.Recorded == nil
}

// EngineLines are the engine lines of the summary (step 5), none when the
// code carries no engine key.
func (p *Prepared) EngineLines() []string {
	if p.Engine.Key == nil {
		return nil
	}
	agent := AgentWord(p.P)
	line := fmt.Sprintf("This records engine %s for %s.", channel.FingerprintOf(p.Engine.ID), agent)
	out := []string{line, fmt.Sprintf("Check that %s's status tool shows the same engine fingerprint (vault.fingerprint).", agent)}
	if v := p.Engine.LastRevoked; v != nil {
		out = append(out, fmt.Sprintf("This database revoked engine %s on %s. Recording a new engine trusts the agent's server again: "+
			"do it only if you rebuilt or replaced that server.", channel.FingerprintOf(v.ID), UTCMinute(*v.RevokedAt)))
	}
	return out
}

// engineStatements are record_engine for the code's engine, run on a
// guard at the installed version or the code's guard.to, whichever is
// later; nothing when the code carries none.
func (p *Prepared) engineStatements() []guardmodel.Statement {
	if p.Engine.Key == nil {
		return nil
	}
	return []guardmodel.Statement{p.be.RecordEngineStatement(p.Engine.Key, max(p.State.GuardVersion, p.P.Guard.To))}
}

func UTCMinute(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
