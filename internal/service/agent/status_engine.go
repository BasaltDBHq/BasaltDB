package agent

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// EngineDownStatus is status as the shim answers it when the engine socket
// does not answer: engine unreachable, guard UNKNOWN, operatedBy from the
// config the shim could read (cfg nil: it could not, so PERSON and
// GUARD_ONLY), the pending setup when the config holds one.
func EngineDownStatus(host EngineHost, name string, cmds guidance.Commands, cfg *config.Config, cfgErr error, build string, now time.Time) (StatusReport, error) {
	return EngineDownStatusAfterStart(host, name, cmds, cfg, cfgErr, build, now, "", "")
}

// EngineDownStatusAfterStart is EngineDownStatus for a basalt mcp that tried
// to start the engine: startFailure, when not empty, is why it could not
// ("basalt mcp could not start the engine: <reason>. Its log is <path>."),
// shown as the problem ENGINE_START_FAILED before ENGINE_UNREACHABLE, whose
// steps stay.
func EngineDownStatusAfterStart(host EngineHost, name string, cmds guidance.Commands, cfg *config.Config, cfgErr error, build string, now time.Time, startFailure, configPath string) (StatusReport, error) {
	r := StatusReport{
		Agent: name, OperatedBy: mcpcontract.OperatedByPerson, Enforcement: EnforcementGuardOnly,
		Engine: EngineStatus{Reachable: false, Build: build},
		Guard:  GuardStatus{State: guardmodel.GuardUnknown, Build: host.LatestGuardVersion()},
		Setup:  SetupStatus{State: setupNone},
		Pages:  PagesStatus{URL: links.DefaultLocal},
	}
	if cfg != nil {
		cmds = cmds.OperatedBy(cfg.OperatedBy)
	}
	ps := Problems{Cmds: cmds}
	msg := "the engine does not answer, so no tool but status works"
	if config.IsOldCredentialFile(cfgErr) {
		// The engine cannot start on this config: say what to edit.
		msg += "; engine.json: " + cfgErr.Error()
	}
	if startFailure != "" {
		ps.Add(problemEngineStartFailed, startFailure,
			func(b *guidance.Steps) string { return engineUnreachableSteps(b, cmds, guidance.ToolStatus) })
	}
	ps.Add(problemEngineUnreachable, msg,
		func(b *guidance.Steps) string { return engineUnreachableSteps(b, cmds, guidance.ToolStatus) })
	if cfg != nil {
		if stop, ok := ReadLastStop(cfg.StateDirFor(runtime.GOOS)); ok {
			r.Engine.LastStop = &stop
			ps.Add(problemEngineGaveUp, engineGaveUpMessage(host, stop, configPath, now),
				func(b *guidance.Steps) string { return engineUnreachableSteps(b, cmds, guidance.ToolStatus) })
		}
		r.OperatedBy = operatedBy(cfg.OperatedBy)
		r.Enforcement = enforcement(cfg.OperatedBy, !cfg.Service())
		if base, err := cfg.PagesBase(); err == nil {
			r.Pages.URL = base
		}
		if a, ok := configAgent(cfg, name); ok {
			setup := setupFrom(a.Setup, false, now)
			r.Setup = setup.status
			setup.addProblem(&ps)
		}
	}
	list, err := ps.Sorted()
	if err != nil {
		return StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

// engineRecordStatus reads this engine's record for status and adds its
// problem ENGINE_REVOKED. Without the engine's
// key (the key file is refused) or a readable guard of version 33 or later,
// the state is UNKNOWN and no problem is added.
func (s statusDeps) engineRecordStatus(ctx context.Context, engineID string, guardReadable bool, ps *Problems) *EngineRecordStatus {
	unknown := &EngineRecordStatus{State: engineUnknown}
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
		return &EngineRecordStatus{State: engineNotRecorded}
	}
	out := &EngineRecordStatus{State: engineRecorded, RecordedAt: e.RecordedAt.UTC().Format(time.RFC3339)}
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

// startedByEnum is the status enum of a --started-by value ("" for none).
func startedByEnum(v string) string {
	switch v {
	case "hand", "mcp", "crash":
		return strings.ToUpper(v)
	}
	return ""
}

// lastStopFile is what the engine's supervisor writes in the state
// directory when it gives up (cmd/basalt, basalt engine --supervise).
const lastStopFile = "last-stop.json"

// maxLastStopBytes bounds what is read of it; maxReasonRunes what is shown.
const (
	maxLastStopBytes = 4096
	maxReasonRunes   = 300
)

// ReadLastStop reads why the supervisor gave up, from dir (the state
// directory): ok is false when there is no usable record. It is read as
// text and shown, never trusted for anything else.
func ReadLastStop(dir string) (LastStop, bool) {
	// Not a symlink, and never blocking on a pipe someone left there.
	f, err := os.OpenFile(filepath.Join(dir, lastStopFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return LastStop{}, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return LastStop{}, false
	}
	var rec lastStopJSON
	if err := json.NewDecoder(io.LimitReader(f, maxLastStopBytes)).Decode(&rec); err != nil || rec.Reason == "" {
		return LastStop{}, false
	}
	if r := []rune(rec.Reason); len(r) > maxReasonRunes {
		rec.Reason = string(r[:maxReasonRunes])
	}
	rec.Reason = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, rec.Reason)
	return LastStop{Reason: rec.Reason, At: rec.At.UTC(), EngineSHA256: rec.EngineSHA256}, true
}

// engineGaveUpMessage is the ENGINE_GAVE_UP status message: the supervisor's
// reason, and when the next try happens during the hold-off.
func engineGaveUpMessage(host EngineHost, stop LastStop, configPath string, now time.Time) string {
	msg := "the engine stopped and was not restarted: " + stop.Reason
	if until, ok := host.StartHoldOffUntil(stop, configPath, now); ok {
		msg += ". The next try is at " + until.UTC().Format(time.RFC3339) + "."
	}
	return msg
}

// lastStopJSON is last-stop.json: why the supervisor gave up, when, and the
// SHA-256 of engine.json at that moment.
type lastStopJSON struct {
	Reason       string    `json:"reason"`
	At           time.Time `json:"at"`
	EngineSHA256 string    `json:"engineSha256,omitempty"`
}
