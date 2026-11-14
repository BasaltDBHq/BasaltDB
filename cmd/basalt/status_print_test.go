package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// A step the person message already names is printed once: NO_PASSKEY's
// message ends "Run: <command>", so no second Run line follows it.
func TestStatusPrintsEachCommandOnce(t *testing.T) {
	t.Parallel()
	const cmd = "basalt init --agent bot --add-passkey"
	var b strings.Builder
	writeStatus(&b, statusOut{StatusReport: agent.StatusReport{Agent: "bot", Problems: []agent.Problem{
		{
			Code: "NO_PASSKEY", Severity: "WARNING", Message: "no passkey", PersonMessage: "No passkey is registered. Run: " + cmd,
			NextSteps: []agent.NextStep{{Command: cmd}},
		},
		{
			Code: "GUARD_OUTDATED", Severity: "ERROR", Message: "old guard", PersonMessage: "The guard is old.",
			NextSteps: []agent.NextStep{{Command: "basalt upgrade --agent bot"}},
		},
	}}})
	out := b.String()
	require.Equal(t, 1, strings.Count(out, cmd), out)
	require.Contains(t, out, "Run: basalt upgrade --agent bot", "a step the message does not name is printed")
}

// The engine's record is printed with its address, and the REVOKED line
// says approvals go on.
func TestStatusPrintsTheEngineRecord(t *testing.T) {
	t.Parallel()
	for state, want := range map[string]string{
		"RECORDED":     "Engine key:   RECORDED in the agent's database, engine.example.com (since 2026-11-12T09:00:00Z)",
		"REVOKED":      "Engine key:   REVOKED 2026-11-12T10:00:00Z",
		"NOT_RECORDED": "Engine key:   NOT_RECORDED",
		"UNKNOWN":      "Engine key:   UNKNOWN",
	} {
		var b strings.Builder
		writeStatus(&b, statusOut{StatusReport: agent.StatusReport{Agent: "bot", EngineRecord: &agent.EngineRecordStatus{
			State: state, URL: "https://engine.example.com", RecordedAt: "2026-11-12T09:00:00Z", RevokedAt: "2026-11-12T10:00:00Z",
		}}})
		require.Contains(t, b.String(), want, state)
	}
	var b strings.Builder
	writeStatus(&b, statusOut{StatusReport: agent.StatusReport{Agent: "bot"}})
	require.NotContains(t, b.String(), "Engine key:", "an engine that is down has no record to print")
}

// basalt status on an engine in the foreground reports the engine record
// only for a running engine whose key file it reads, and the engine serves
// the direct transport only with a direct listener and a key.
func TestRunningEngineKey(t *testing.T) {
	t.Parallel()
	direct := config.Config{PagesURL: links.Portal, DirectAddr: "127.0.0.1:8788"}
	off := config.Config{PagesURL: links.Portal, DirectAddr: config.PagesOff}
	up := engineOut{Reachable: true}
	id := &agent.VaultStatus{EngineID: "AAAAAAAAAAAAAAAAAAAAAA"}
	keyError := &agent.VaultStatus{State: "KEY_ERROR"}
	off2 := &agent.VaultStatus{State: "OFF", EngineID: "BBBBBBBBBBBBBBBBBBBBBB"}

	key, served := runningEngineKey(up, nil, id, direct)
	require.Equal(t, "AAAAAAAAAAAAAAAAAAAAAA", *key)
	require.True(t, served)
	key, served = runningEngineKey(up, off2, nil, off)
	require.Equal(t, "BBBBBBBBBBBBBBBBBBBBBB", *key)
	require.False(t, served, "directAddr off")
	key, served = runningEngineKey(up, keyError, nil, direct)
	require.Empty(t, *key, "the key file is refused: UNKNOWN")
	require.False(t, served, "no key, no direct listener")

	key, _ = runningEngineKey(engineOut{}, nil, id, direct)
	require.Nil(t, key, "an engine that is down")
	key, _ = runningEngineKey(up, nil, nil, direct)
	require.Nil(t, key, "a key file this user cannot read")
}
