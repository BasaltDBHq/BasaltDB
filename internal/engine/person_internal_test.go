//go:build linux || darwin

package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

func TestListenPersonOpensTheSocketLikeTheAgentSockets(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bep") // short: Unix socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := config.Config{SocketDir: filepath.Join(dir, "run"), Mode: config.ModeService, PersonUIDs: []uint32{4242}}

	srv, ln, err := listenPerson(cfg, map[string]person.Ledger{}, map[string]uint32{}, person.PagesDTO{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	path := filepath.Join(dir, "run", "person.sock")
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(socketMode), fi.Mode().Perm(), "0666: the peer uid allowlist is the access control")
	di, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(socketDirMode), di.Mode().Perm())

	// This process is the engine: its own uid is refused although nothing
	// else is recorded.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	_, err = person.Client{Path: path}.Pages(ctx)
	require.True(t, errors.Is(err, person.ErrUIDNotAllowed), "%v", err)
	cancel()
	<-done
	_, err = os.Stat(path)
	require.True(t, errors.Is(err, os.ErrNotExist), "the socket goes when the engine stops")
}

// passkeysOnly is a Ledger that answers ListPasskeys; any other call
// panics, so a refused request that reached it would fail the test.
type passkeysOnly struct{ person.Ledger }

func (passkeysOnly) ListPasskeys(context.Context) ([]ledger.Passkey, error) { return nil, nil }

func TestAStaleAgentsOSUserStaysScoped(t *testing.T) {
	t.Parallel()
	users := map[string]uint32{"botuser": 5001, "staleuser": 5002}
	lookup := func(name string) (uint32, error) {
		uid, ok := users[name]
		if !ok {
			return 0, fmt.Errorf("os user %q: unknown", name)
		}
		return uid, nil
	}
	bot := config.Agent{Name: "bot", OSUser: "botuser", CredentialFile: "/c/bot.url"}
	stale := config.Agent{Name: "stale", OSUser: "staleuser", CredentialFile: "/c/stale.url"}
	cfg := config.Config{SocketDir: "/run/basalt", Agents: []config.Agent{stale}}

	// The stale agent is skipped, but its OS user is still known.
	uids, err := agentOSUIDs([]config.Agent{bot, stale}, lookup)
	require.NoError(t, err)
	require.Equal(t, map[string]uint32{"bot": 5001, "stale": 5002}, uids)
	started, err := startAgents(context.Background(), cfg, agentEnv{}, uids,
		func(context.Context, agentEnv, config.Agent, *slog.Logger) (agentRuntime, error) {
			return agentRuntime{}, &guard.StaleSchemaError{Installed: 1, Latest: 2}
		}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Empty(t, started.agents)
	require.Empty(t, started.ledgers, "a stale agent serves no ledger")

	// An OS user that does not resolve stops the engine (fail closed).
	_, err = agentOSUIDs([]config.Agent{bot, {Name: "ghost", OSUser: "nobody-here"}}, lookup)
	require.ErrorContains(t, err, "agent ghost")

	// The stale agent's user, recorded as a person, still sees only its own
	// agent: never the served bot.
	ledgers := map[string]person.Ledger{"bot": passkeysOnly{}}
	call := func(peer uint32, agent string) error {
		dir, err := os.MkdirTemp("", "bes")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })
		path := filepath.Join(dir, "person.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		require.NoError(t, err)
		srv := person.NewServer(person.Options{
			Allow: []uint32{5002, 5003}, Agents: ledgers, AgentUIDs: uids,
			PeerUID: func(*net.UnixConn) (uint32, error) { return peer, nil }, Log: slog.New(slog.DiscardHandler),
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { srv.Serve(ctx, ln); close(done) }()
		defer func() { cancel(); <-done }()
		_, err = person.Client{Path: path}.Agent(agent).ListPasskeys(ctx)
		return err
	}
	var we *person.Error
	require.ErrorAs(t, call(5002, "bot"), &we)
	require.Equal(t, person.CodeAgentNotAllowed, we.Code)
	require.ErrorAs(t, call(5002, "stale"), &we)
	require.Equal(t, person.CodeUnknownAgent, we.Code, "its own agent, not served")
	require.NoError(t, call(5003, "bot"), "the person runs no agent and sees bot")
}
