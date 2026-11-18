//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

const (
	shopDSN  = "postgres://basalt_agent_shop:s3cretShop@shop.db.example.com:6543/shopdb?sslmode=require"
	salesDSN = "postgres://basalt_agent_sales:s3cretSales@sales.db.example.com:5432/salesdb"
)

// multiConfig writes an engine.json with agents shop and sales on different
// databases and returns its path.
func multiConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	short, err := os.MkdirTemp("", "bst")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(short) })
	me, err := user.Current()
	require.NoError(t, err)
	agents := make([]map[string]any, 0, 2)
	for name, dsn := range map[string]string{"shop": shopDSN, "sales": salesDSN} {
		cred := filepath.Join(dir, "agents", name+".url")
		require.NoError(t, os.MkdirAll(filepath.Dir(cred), 0o700))
		require.NoError(t, os.WriteFile(cred, []byte(dsn+"\n"), config.FileMode))
		agents = append(agents, map[string]any{
			"name": name, "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": cred},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"socketDir": short, "stateDir": filepath.Join(dir, "state"),
		"pagesAddr": "off", "mode": "SAME_USER", "agents": agents,
	})
	require.NoError(t, err)
	path := filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func requireNoCredential(t *testing.T, out string) {
	t.Helper()
	for _, secret := range []string{"s3cretShop", "s3cretSales", "postgres://", "basalt_agent_", ":6543", "agents/", ".url"} {
		require.NotContains(t, out, secret)
	}
}

func TestStatusListsEveryAgentAndItsDatabaseForAPerson(t *testing.T) {
	t.Parallel()
	cfg := multiConfig(t)

	r := cliCmd(t, runStatus, nil, "", "--config", cfg)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Regexp(t, `AGENT\s+HOST\s+DATABASE`, r.stdout)
	require.Regexp(t, `sales\s+sales\.db\.example\.com\s+salesdb`, r.stdout)
	require.Regexp(t, `shop\s+shop\.db\.example\.com\s+shopdb`, r.stdout)
	require.Contains(t, r.stdout, "basalt status --agent NAME prints one agent's full report.")
	requireNoCredential(t, r.stdout+r.stderr)

	j := cliCmd(t, runStatus, nil, "", "--config", cfg, "--json")
	require.Equal(t, exitOK, j.code, j.stderr)
	requireNoCredential(t, j.stdout)
	var out struct {
		Agents []map[string]any `json:"agents"`
	}
	require.NoError(t, json.Unmarshal([]byte(j.stdout), &out))
	require.ElementsMatch(t, []map[string]any{
		{"agent": "shop", "host": "shop.db.example.com", "database": "shopdb"},
		{"agent": "sales", "host": "sales.db.example.com", "database": "salesdb"},
	}, out.Agents)
}

func TestStatusUnderAnAgentMarkerListsNoOtherAgent(t *testing.T) {
	t.Parallel()
	cfg := multiConfig(t)
	for _, marker := range []string{"CLAUDECODE", "CODEX_SANDBOX", "BASALT_AGENT_CONTEXT"} {
		r := cliCmd(t, runStatus, map[string]string{marker: "1"}, "", "--config", cfg)
		require.Equal(t, exitUsage, r.code, marker)
		require.Contains(t, r.stderr, "give --agent NAME")
		require.Contains(t, r.stderr, "The person can see every agent and its database by running basalt status in their own terminal.")
		out := r.stdout + r.stderr
		for _, other := range []string{"shop", "sales", "shopdb", "salesdb", "example.com"} {
			require.NotContains(t, out, other, marker)
		}
	}
}

func TestStatusAgentIsStillTheFullReportWithItsDatabase(t *testing.T) {
	t.Parallel()
	g := newOlderGuard(t, 0)
	r := g.status(t, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	g.requireNoSecret(t, r.stdout)
	var out struct {
		Database map[string]string `json:"database"`
		Agent    string            `json:"agent"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, "bot", out.Agent)
	require.NotEmpty(t, out.Database["host"])
	require.NotEmpty(t, out.Database["name"])
	require.Len(t, out.Database, 2, "name and host only")

	text := g.status(t, "--agent", "bot")
	require.Contains(t, text.stdout, "  Database:   "+out.Database["name"]+" on "+out.Database["host"])
	g.requireNoSecret(t, text.stdout)
}

// multiEngine is a service-mode engine's person socket with agents shop and
// sales; the fake only needs TARGET and AGENTS.
func multiEngine(t *testing.T, uid uint32) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bst")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "person.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	info := func(host, db string) person.AgentInfo {
		return person.AgentInfo{
			Status: func(context.Context) (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
			Target: person.TargetDTO{Host: host, Port: 6543, Database: db},
		}
	}
	srv := person.NewServer(person.Options{
		Allow:   []uint32{uid},
		PeerUID: func(*net.UnixConn) (uint32, error) { return uid, nil },
		Log:     slog.New(slog.DiscardHandler),
		Info:    map[string]person.AgentInfo{"shop": info("shop.db.example.com", "shopdb"), "sales": info("sales.db.example.com", "salesdb")},
		Engine:  person.EngineInfo{Engine: person.EngineDTO{PID: 77, OSUser: "basalt"}, SocketDir: "/run/basalt", StateDir: "/var/lib/basalt"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

func TestStatusListsAgentsThroughThePersonSocketInServiceMode(t *testing.T) {
	t.Parallel()
	socket := multiEngine(t, personUIDForTest)

	r := serviceCmd(t, runStatus, socket, nil)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Regexp(t, `sales\s+sales\.db\.example\.com\s+salesdb`, r.stdout)
	require.Regexp(t, `shop\s+shop\.db\.example\.com\s+shopdb`, r.stdout)
	require.Less(t, strings.Index(r.stdout, "sales"), strings.Index(r.stdout, "shop"), "sorted by agent")
	requireNoCredential(t, r.stdout)

	j := serviceCmd(t, runStatus, socket, nil, "--json")
	require.Equal(t, exitOK, j.code, j.stderr)
	require.Contains(t, j.stdout, `"database": "salesdb"`)
	require.NotContains(t, j.stdout, "6543", "no port")

	marked := serviceCmd(t, runStatus, socket, map[string]string{"CLAUDECODE": "1"})
	require.Equal(t, exitUsage, marked.code)
	require.Contains(t, marked.stderr, "give --agent NAME")
	require.Contains(t, marked.stderr, "in their own terminal")
	for _, other := range []string{"shop", "sales", "example.com"} {
		require.NotContains(t, marked.stdout+marked.stderr, other)
	}
}

func TestAgentsOverThePersonSocketAreScopedToTheCaller(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bst")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "person.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	const agentUID = 4242
	srv := person.NewServer(person.Options{
		Allow:   []uint32{agentUID},
		PeerUID: func(*net.UnixConn) (uint32, error) { return agentUID, nil },
		Log:     slog.New(slog.DiscardHandler),
		Info: map[string]person.AgentInfo{
			"shop":  {Target: person.TargetDTO{Host: "shop.db.example.com", Database: "shopdb"}},
			"sales": {Target: person.TargetDTO{Host: "sales.db.example.com", Database: "salesdb"}},
		},
		AgentUIDs: map[string]uint32{"shop": agentUID, "sales": 9999},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	got, err := person.Client{Path: path}.Agents(context.Background())
	require.NoError(t, err)
	require.Equal(t, []person.AgentDTO{{Agent: "shop", Host: "shop.db.example.com", Database: "shopdb"}}, got)
}
