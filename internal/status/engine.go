package status

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// EngineDownStatusAfterStart is status as the shim answers it when the engine
// socket does not answer: engine unreachable, guard UNKNOWN, operatedBy from
// the config the shim could read (cfg nil: it could not, so PERSON and
// GUARD_ONLY), the pending setup when the config holds one. For a basalt mcp
// that tried to start the engine, startFailure, when not empty, is why it could not
// ("basalt mcp could not start the engine: <reason>. Its log is <path>."),
// shown as the problem ENGINE_START_FAILED before ENGINE_UNREACHABLE, whose
// steps stay.
func EngineDownStatusAfterStart(host EngineHost, name string, cmds guidance.Commands, cfg *config.Config, cfgErr error, build string, now time.Time, startFailure, configPath string) (guidance.StatusReport, error) {
	r := guidance.StatusReport{
		Agent: name, OperatedBy: mcpcontract.OperatedByPerson, Enforcement: enforcementGuardOnly,
		Engine: guidance.EngineStatus{Reachable: false, Build: build},
		Guard:  guidance.GuardStatus{State: guardmodel.GuardUnknown, Build: host.LatestGuardVersion()},
		Setup:  guidance.SetupStatus{State: handoff.SetupNone},
		Pages:  guidance.PagesStatus{URL: links.DefaultLocal},
	}
	if cfg != nil {
		cmds = cmds.OperatedBy(cfg.OperatedBy)
	}
	ps := guidance.Problems{Cmds: cmds}
	if ConfigUnloadable(cfg, cfgErr) {
		r.OperatedBy = config.SniffOperatedBy(configPath)
		ps.Add(problemConfigInvalid, "engine.json cannot be loaded: "+cfgErr.Error(),
			func(b *guidance.Steps) string { return guidance.ConfigInvalidSteps(b, name) })
		list, err := ps.Sorted()
		if err != nil {
			return guidance.StatusReport{}, err
		}
		r.Problems, r.Ready = list, Ready(list)
		return r, nil
	}
	msg := "the engine does not answer, so no tool but status works"
	if config.IsOldCredentialFile(cfgErr) {
		// The engine cannot start on this config: say what to edit.
		msg += "; engine.json: " + cfgErr.Error()
	}
	if startFailure != "" {
		ps.Add(problemEngineStartFailed, startFailure,
			func(b *guidance.Steps) string { return guidance.EngineUnreachableSteps(b, cmds, guidance.ToolStatus) })
	}
	ps.Add(problemEngineUnreachable, msg,
		func(b *guidance.Steps) string { return guidance.EngineUnreachableSteps(b, cmds, guidance.ToolStatus) })
	if cfg != nil {
		if stop, ok := host.ReadLastStop(cfg.StateDirFor(runtime.GOOS)); ok {
			r.Engine.LastStop = &stop
			ps.Add(problemEngineGaveUp, EngineGaveUpMessage(host, stop, configPath, now),
				func(b *guidance.Steps) string { return guidance.EngineUnreachableSteps(b, cmds, guidance.ToolStatus) })
		}
		r.OperatedBy = OperatedBy(cfg.OperatedBy)
		r.Enforcement = Enforcement(cfg.OperatedBy, !cfg.Service())
		if base, err := cfg.PagesBase(); err == nil {
			r.Pages.URL = base
		}
		if a, ok := configAgent(cfg, name); ok {
			setup := handoff.SetupFrom(a.Setup, false, now)
			r.Setup = setup.Status
			setup.AddProblem(&ps)
		}
	}
	list, err := ps.Sorted()
	if err != nil {
		return guidance.StatusReport{}, err
	}
	r.Problems, r.Ready = list, Ready(list)
	return r, nil
}

// engineRecordStatus reads this engine's record for status and adds its
// problem ENGINE_REVOKED. Without the engine's
// key (the key file is refused) or a readable guard of version 33 or later,
// the state is UNKNOWN and no problem is added.
// ConfigUnloadable reports a config that exists and failed to load: the
// engine cannot start from it, and its mode is not known. A missing file is
// not one.
func ConfigUnloadable(cfg *config.Config, cfgErr error) bool {
	return cfg == nil && cfgErr != nil && !errors.Is(cfgErr, fs.ErrNotExist)
}

func (s statusDeps) engineRecordStatus(ctx context.Context, engineID string, guardReadable bool, ps *guidance.Problems) *guidance.EngineRecordStatus {
	unknown := &guidance.EngineRecordStatus{State: engineUnknown}
	if engineID == "" || !guardReadable || s.engineRecord == nil {
		return unknown
	}
	rctx, cancel := context.WithTimeout(ctx, engineRecordTimeout)
	defer cancel()
	e, err := s.engineRecord(rctx, engineID)
	if err != nil {
		s.log.Debug("status: read the engine's record", "err", err)
		return unknown
	}
	if e == nil {
		return &guidance.EngineRecordStatus{State: engineNotRecorded}
	}
	out := &guidance.EngineRecordStatus{State: engineRecorded, RecordedAt: e.RecordedAt.UTC().Format(time.RFC3339)}
	if e.RevokedAt != nil {
		out.State, out.RevokedAt = engineRevoked, e.RevokedAt.UTC().Format(time.RFC3339)
		ps.Add(problemEngineRevoked, "the agent's database revoked this engine's key; the engine does not act on it, so the links it handed over keep working until they expire",
			engineRevokedSteps)
	}
	return out
}

// engineRevokedSteps: the agent asks whether the person revoked this engine
// on purpose.
func engineRevokedSteps(b *guidance.Steps) string {
	b.AskPerson("Tell the person this engine's key is revoked in their database. Ask whether they revoked it on purpose, and show the message.")
	b.EndTurn("End your turn: the person answers next.")
	return "This engine's key is revoked in your database. BasaltDB does not act on it: the links this engine handed over keep working until they expire. To cut this engine off, remove BasaltDB from the database. " +
		"Did you revoke it on purpose? If you replaced the engine, the agent sets it up again and gives you a new link."
}

// StartedByEnum is the status enum of a --started-by value ("" for none).
func StartedByEnum(v string) string {
	switch v {
	case "hand", "mcp", "crash":
		return strings.ToUpper(v)
	}
	return ""
}

// EngineGaveUpMessage is the ENGINE_GAVE_UP status message: the supervisor's
// reason, and when the next try happens during the hold-off.
func EngineGaveUpMessage(host EngineHost, stop guidance.LastStop, configPath string, now time.Time) string {
	msg := "the engine stopped and was not restarted: " + stop.Reason
	if until, ok := host.StartHoldOffUntil(stop, configPath, now); ok {
		msg += ". The next try is at " + until.UTC().Format(time.RFC3339) + "."
	}
	return msg
}

// EngineHost is what the status of an engine that is down reads from the
// host: the guard version this build installs, why the supervisor gave up
// (last-stop.json in the state directory), and when it tries the engine
// again after that.
type EngineHost struct {
	LatestGuardVersion func() int
	ReadLastStop       func(stateDir string) (guidance.LastStop, bool)
	StartHoldOffUntil  func(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool)
}
