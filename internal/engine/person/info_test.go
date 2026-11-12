//go:build linux || darwin

package person_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

func TestStatusAndTargetAnswerWithoutTheLedger(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refused := &fakeLedger{err: errors.New("the guard is outdated")}
	info := person.AgentInfo{
		Status: func(context.Context) (json.RawMessage, error) {
			return json.RawMessage(`{"agent":"bot","ready":false}`), nil
		},
		Target: person.TargetDTO{Host: "db.example.com", Port: 5432, Database: "app"},
	}
	c := serveWith(t, person.Options{
		Allow:   []uint32{personUID},
		Agents:  map[string]person.Ledger{"bot": refused},
		Info:    map[string]person.AgentInfo{"bot": info},
		Engine:  person.EngineInfo{Engine: person.EngineDTO{PID: 9, OSUser: "basalt"}, SocketDir: "/run/basalt", StateDir: "/var/lib/basalt"},
		PeerUID: peerIs(personUID),
	})
	st, err := c.Status(ctx, "bot")
	require.NoError(t, err)
	require.JSONEq(t, `{"agent":"bot","ready":false}`, string(st.Status))
	require.Equal(t, person.EngineDTO{PID: 9, OSUser: "basalt"}, st.Engine)
	require.Equal(t, "/run/basalt", st.SocketDir)
	require.Equal(t, "/var/lib/basalt", st.StateDir)
	target, err := c.Target(ctx, "bot")
	require.NoError(t, err)
	require.Equal(t, info.Target, target)
	require.Zero(t, refused.calls.Load(), "neither reads the ledger, so both answer while the guard check refuses it")

	_, err = c.Status(ctx, "nobody")
	var we *person.Error
	require.ErrorAs(t, err, &we)
	require.Equal(t, person.CodeUnknownAgent, we.Code)
}

func TestStatusAndTargetKeepAnAgentsOSUserToItsOwnAgent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	info := person.AgentInfo{
		Status: func(context.Context) (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Target: person.TargetDTO{Host: "h", Port: 1, Database: "d"},
	}
	c := serveWith(t, person.Options{
		Allow:     []uint32{agentUID},
		Agents:    map[string]person.Ledger{"bot": &fakeLedger{}, "other": &fakeLedger{}},
		Info:      map[string]person.AgentInfo{"bot": info, "other": info},
		AgentUIDs: map[string]uint32{"other": agentUID},
		PeerUID:   peerIs(agentUID),
	})
	_, err := c.Status(ctx, "other")
	require.NoError(t, err)
	for _, call := range []func() error{
		func() error { _, err := c.Status(ctx, "bot"); return err },
		func() error { _, err := c.Target(ctx, "bot"); return err },
	} {
		var we *person.Error
		require.ErrorAs(t, call(), &we)
		require.Equal(t, person.CodeAgentNotAllowed, we.Code)
	}
}
