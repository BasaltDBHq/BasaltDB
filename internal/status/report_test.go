package status

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// basalt status on an engine run in the foreground reads the record too:
// the engine id from the running engine's key file, the record through the
// agent's own database, with the same problems as the status tool.
func TestLocalStatusEngineRecord(t *testing.T) {
	t.Parallel()
	local := func(key *string, read EngineRecordReader) guidance.StatusReport {
		t.Helper()
		cmds := commandsAt("")
		r, err := localStatus{
			Errors: testErrors(), LatestGuardVersion: guard.LatestVersion,
			Name: "bot", Commands: cmds, EngineRunning: true, EngineKey: key, EngineRecord: read,
			Probe: &fakeProbe{st: currentGuard()},
			Passkeys: func(context.Context) ([]passkey.Credential, error) {
				return []passkey.Credential{{Relying: passkey.Relying{Origin: links.DefaultLocal}}}, nil
			},
			Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
		}.report(context.Background())
		require.NoError(t, err)
		return r
	}
	id := testEngineID
	r := local(&id, recordOf(false))
	require.Equal(t, "RECORDED", r.EngineRecord.State)
	require.Empty(t, r.Problems)

	r = local(&id, recordOf(true))
	require.Equal(t, "REVOKED", r.EngineRecord.State)
	findProblem(t, r, "ENGINE_REVOKED")

	refused := ""
	r = local(&refused, recordOf(true))
	require.Equal(t, &guidance.EngineRecordStatus{State: "UNKNOWN"}, r.EngineRecord, "the key file is refused")
	require.Empty(t, r.Problems)

	require.Nil(t, local(nil, recordOf(true)).EngineRecord, "an engine that is down has none")
}

func TestStatusEnforcementAndOperator(t *testing.T) {
	t.Parallel()
	require.Equal(t, enforcementGuardOnly, Enforcement(mcpcontract.OperatedByAgent, false))
	require.Equal(t, enforcementGuardOnly, Enforcement(mcpcontract.OperatedByPerson, true), "same-user mode")
	require.Equal(t, enforcementEngineAndGuard, Enforcement("", false))
	require.Equal(t, mcpcontract.OperatedByPerson, OperatedBy(""))

	// The shim that cannot read the config: PERSON and GUARD_ONLY.
	cmds := commandsAt("")
	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Equal(t, mcpcontract.OperatedByPerson, r.OperatedBy)
	require.Equal(t, enforcementGuardOnly, r.Enforcement)
	require.False(t, r.Engine.Reachable)
	require.False(t, r.Ready)
	require.Equal(t, handoff.SetupNone, r.Setup.State)
	require.Equal(t, osservice.StartCommand("linux"), r.Problems[0].NextSteps[0].Command)

	// A same-user config the shim reads: its operator and its foreground engine.
	cfg := &config.Config{SocketDir: "/run/basalt", OperatedBy: mcpcontract.OperatedByAgent, Agents: []config.Agent{{
		Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential), Setup: pendingSetup(guardmodel.SetupInstall, statusNow.Add(time.Hour)),
	}}}
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds.Foreground(), cfg, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Equal(t, mcpcontract.OperatedByAgent, r.OperatedBy)
	require.Equal(t, enforcementGuardOnly, r.Enforcement)
	require.Equal(t, "PENDING", r.Setup.State)
	require.Equal(t, "a1b2 c3d4 e5f6 0718 293a", r.Setup.Fingerprint)
	require.Equal(t, "basalt engine --config /etc/basalt/engine.json", findProblem(t, r, guidance.ReasonEngineUnreachable).NextSteps[0].Command)
	findProblem(t, r, "SETUP_NOT_RUN")
}

func TestEngineDownStatusLastStop(t *testing.T) {
	t.Parallel()
	cmds := commandsAt("")
	dir := t.TempDir()
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}

	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Nil(t, r.Engine.LastStop, "no file, no last stop")

	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.LastStopFile), []byte("{\"reason\":\"the engine crashed 5 times within 10s; last: exit status 1\\u0007\",\"at\":\"2026-11-20T01:02:03Z\"}"), 0o600))
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.NotNil(t, r.Engine.LastStop)
	require.Equal(t, "the engine crashed 5 times within 10s; last: exit status 1 ", r.Engine.LastStop.Reason, "unprintable characters are blanked")
	require.Equal(t, time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC), r.Engine.LastStop.At)
	p := findProblem(t, r, "ENGINE_GAVE_UP")
	require.Contains(t, p.Message, "the engine crashed 5 times within 10s")
	findProblem(t, r, guidance.ReasonEngineUnreachable)

	// A file that is not a record shows nothing.
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.LastStopFile), []byte("not json"), 0o600))
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Nil(t, r.Engine.LastStop)
}

func TestEngineDownStatusHoldOffNamesTheNextTry(t *testing.T) {
	t.Parallel()
	cmds := commandsAt("")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("v1\n"), 0o600))
	at := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	rec, err := json.Marshal(servicespec.LastStopFileRecord{
		Reason: "the engine crashed 5 times within 10s; last: exit status 1",
		At:     at, EngineSHA256: laststop.HashEngineJSON(cfgPath),
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.LastStopFile), rec, 0o600))
	cfg := &config.Config{SocketDir: "/run/basalt", StateDir: dir, Agents: []config.Agent{{Name: "bot", OSUser: "bot", Store: config.PostgresStore(statusCredential)}}}
	now := at.Add(30 * time.Second)

	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", now, "", cfgPath)
	require.NoError(t, err)
	p := findProblem(t, r, "ENGINE_GAVE_UP")
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1. The next try is at 2026-11-21T08:01:00Z.", p.Message)
	// lastStop on the wire stays {reason, at}.
	raw, err := json.Marshal(r.Engine.LastStop)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "engineSha256")
	require.JSONEq(t, `{"reason":"the engine crashed 5 times within 10s; last: exit status 1","at":"2026-11-21T08:00:00Z"}`, string(raw))

	// After the minute, the next-try sentence is gone; the reason stays.
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", at.Add(time.Minute), "", cfgPath)
	require.NoError(t, err)
	p = findProblem(t, r, "ENGINE_GAVE_UP")
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1", p.Message)

	// Editing engine.json ends the hold-off message too.
	require.NoError(t, os.WriteFile(cfgPath, []byte("v2\n"), 0o600))
	r, err = EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, cfg, nil, "test", now, "", cfgPath)
	require.NoError(t, err)
	p = findProblem(t, r, "ENGINE_GAVE_UP")
	require.Equal(t, "the engine stopped and was not restarted: the engine crashed 5 times within 10s; last: exit status 1", p.Message)
}

// A config refused for the older credentialFile key puts the edit in the
// shim's status, since the engine cannot start on it.
func TestEngineDownStatusNamesTheOldCredentialFileEdit(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir": "/s", "agents": [{"name": "bot", "osUser": "u", "credentialFile": "/c/bot.cred"}]}`), 0o600))
	_, cfgErr := config.Load(path)
	cmds := commandsAt(path)
	r, err := EngineDownStatusAfterStart(testEngineHost(), "bot", cmds, nil, cfgErr, "test", statusNow, "", "")
	require.NoError(t, err)
	require.Len(t, r.Problems, 1)
	require.Contains(t, r.Problems[0].Message, `agent "bot": "credentialFile" now goes inside "store"; replace "credentialFile": "/c/bot.cred" with "store": {"kind": "POSTGRES", "credentialFile": "/c/bot.cred"}`)
}
