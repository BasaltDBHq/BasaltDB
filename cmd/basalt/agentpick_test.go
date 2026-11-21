//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// pickIO is a person CLI with nothing in the env.
func pickIO() *cliIO {
	return newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &bytes.Buffer{}}, func(string) string { return "" })
}

// twoAgentConfig is an engine config serving bot and helper.
func twoAgentConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"socketDir": "/s", "agents": [
		{"name": "helper", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c1"}},
		{"name": "bot", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c2"}}]}`), 0o600))
	return path
}

func TestPickAgentFindsTheOwner(t *testing.T) {
	t.Parallel()
	c := pickIO()
	cfg := twoAgentConfig(t)
	owner := func(want string) func(string) (bool, error) {
		return func(a string) (bool, error) { return a == want, nil }
	}

	const item = "approval 0193"
	got, err := pickAgent(c, cfg, item, owner("helper"))
	require.NoError(t, err)
	require.Equal(t, "helper", got, "the agent whose ledger has the item")

	// An agent that cannot be read is skipped.
	got, err = pickAgent(c, cfg, item, func(a string) (bool, error) {
		if a == "bot" {
			return false, errors.New("down")
		}
		return true, nil
	})
	require.NoError(t, err)
	require.Equal(t, "helper", got)

	// No agent holds it: said so, naming the agents.
	_, err = pickAgent(c, cfg, item, owner("nobody"))
	require.EqualError(t, err, "no agent here holds approval 0193 (the engine serves bot, helper)")

	// Both hold it: ask for --agent.
	_, err = pickAgent(c, cfg, item, func(string) (bool, error) { return true, nil })
	require.ErrorIs(t, err, errUsage)
	require.ErrorContains(t, err, "approval 0193 is in the ledgers of bot, helper; give --agent")

	// No agent could be asked (the engine stopped): its error, not a
	// usage error.
	stopped := errors.New("the engine is not running; start it")
	_, err = pickAgent(c, cfg, item, func(string) (bool, error) { return false, stopped })
	require.ErrorIs(t, err, stopped)

	// A config that cannot be read: the usage error as before.
	_, err = pickAgent(c, filepath.Join(t.TempDir(), "missing.json"), item, owner("bot"))
	require.ErrorContains(t, err, "give --agent or "+envAgentURL)
}

// In service mode the agents are the sockets the person can list; with one
// agent, a code or revert id needs no --agent.
func TestServiceModeUsesTheOnlyAgent(t *testing.T) {
	t.Parallel()
	socket := personSocket(t, personUIDForTest)
	ln, err := net.Listen("unix", filepath.Join(filepath.Dir(socket), "bot.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	id := uuid.NewString()
	r := serviceRun(t, socket, runRevert, "--status", id)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no revert "+id+" prepared with this agent's credential", "asked the engine as bot")

	r = serviceRun(t, socket, runApprove, "--show", id)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "approval "+id+" is not a held write of this agent")

	// A code that does not parse is still a usage error about the code.
	r = serviceRun(t, socket, runApprove, "not-a-code")
	require.Equal(t, exitUsage, r.code, r.stderr)
}
