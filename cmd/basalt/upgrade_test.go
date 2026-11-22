//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// olderGuard is a same-user engine setup for agent bot (writes public.leads)
// on a guard installed up to version upTo (0: this build's), as an older
// basalt left it: the role, its grants and its credential file, and an
// engine config in a socket directory short enough for macOS.
type olderGuard struct {
	d          *guardtest.DB
	configPath string
	credFile   string
	socketDir  string
	dsn        string
}

// latestBreaking is the newest version this build flags breaking: a guard
// one below it is outdated, whatever non-breaking versions follow.
func latestBreaking(t *testing.T) int {
	t.Helper()
	migs := guard.Migrations()
	for i := len(migs) - 1; i >= 0; i-- {
		if migs[i].Breaking {
			return migs[i].Version
		}
	}
	t.Fatal("no breaking migration")
	return 0
}

// versionsAfter is every version this build has above installed, as basalt
// upgrade prints them.
func versionsAfter(installed int) string {
	parts := make([]string, 0, guard.LatestVersion()-installed)
	for v := installed + 1; v <= guard.LatestVersion(); v++ {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ", ")
}

func newOlderGuard(t *testing.T, upTo int) olderGuard {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	pw := guard.NewPassword()
	spec := guard.AgentSpec{Name: "bot", Password: pw, Write: []string{"public.leads"}}
	script, err := guard.PlanInit(ctx, d.Admin, guard.InitOptions{Names: d.Names, Agent: spec, UpTo: upTo})
	require.NoError(t, err)
	require.NoError(t, pgx.BeginFunc(ctx, d.Admin, func(tx pgx.Tx) error { return script.Apply(ctx, tx) }))
	role, err := d.Names.Agent("bot")
	require.NoError(t, err)
	dsn, err := guard.AgentConnString(d.URL, role, pw)
	require.NoError(t, err)

	dir, err := os.MkdirTemp("", "bupg") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	g := olderGuard{
		d: d, configPath: filepath.Join(dir, "engine.json"), credFile: filepath.Join(dir, "agents", "bot.url"),
		socketDir: filepath.Join(dir, "run"), dsn: dsn,
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(g.credFile), 0o700))
	require.NoError(t, os.WriteFile(g.credFile, []byte(dsn+"\n"), config.FileMode))
	g.writeConfig(t, "PERSON")
	return g
}

func (g olderGuard) writeConfig(t *testing.T, operatedBy string) {
	t.Helper()
	me, err := user.Current()
	require.NoError(t, err)
	cfg := map[string]any{
		"socketDir": g.socketDir, "stateDir": filepath.Join(filepath.Dir(g.configPath), "state"),
		"pagesAddr": "off", "mode": "SAME_USER", "operatedBy": operatedBy,
		"agents": []map[string]any{{
			"name": "bot", "osUser": me.Username, "store": map[string]any{"kind": "POSTGRES", "credentialFile": g.credFile},
			"initArgs": []string{"--agent=bot", "--write=public.leads", "--prefix=" + g.d.Names.Prefix},
		}},
	}
	if operatedBy == "AGENT" {
		cfg["pagesUrl"] = links.Portal // an agent-operated engine uses the portal (CO-8)
	}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(g.configPath, raw, 0o600))
}

// upgrade runs basalt upgrade for bot with admin (none: not in the
// environment) and stdin.
func (g olderGuard) upgrade(t *testing.T, admin, stdin string, args ...string) result {
	t.Helper()
	env := map[string]string{}
	if admin != "" {
		env[envAdminURL] = admin
	}
	return cliCmd(t, runUpgrade, env, stdin, append([]string{"--agent", "bot", "--config", g.configPath}, args...)...)
}

// cliCmd runs one command with stdin and an environment holding only env.
func cliCmd(t *testing.T, cmd func(*cliIO, []string) int, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string { return env[k] })
	c.engine = engineAccess{unitInstalled: func() bool { return false }}
	code := cmd(c, takePathFlags(c, cmd, args))
	return result{code, stdout.String(), stderr.String()}
}

func (g olderGuard) version(t *testing.T) int {
	t.Helper()
	return installedVersion(t, g.d)
}

// agentStatus is the guard as the agent's credential sees it.
func (g olderGuard) agentStatus(t *testing.T) guard.Status {
	t.Helper()
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, g.dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	st, err := guard.AgentStatus(ctx, conn, guard.Migrations())
	require.NoError(t, err)
	return st
}

// startEngine runs the engine in this process on g's config until the test
// ends, as the person runs it in the foreground.
func (g olderGuard) startEngine(t *testing.T) {
	t.Helper()
	cfg, err := config.Load(g.configPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx, cfg, g.configPath, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	sock := config.SocketPath(g.socketDir, "bot")
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 10*time.Second, 20*time.Millisecond)
}

// callTool calls tool on the running engine's socket for bot, as the
// agent's MCP client does, and returns the tools/call response line.
func (g olderGuard) callTool(t *testing.T, tool string) string {
	t.Helper()
	conn, err := net.Dial("unix", config.SocketPath(g.socketDir, "bot"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	return line
}

func TestUpgradeServesTheRunningEngineAgainWithoutARestart(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	latest := guard.LatestVersion()
	older := latestBreaking(t) - 1
	missing := versionsAfter(older)
	g := newOlderGuard(t, older)
	require.Equal(t, guard.GuardOutdated, g.agentStatus(t).State)
	g.startEngine(t)
	require.Contains(t, g.callTool(t, "list_runs"), "GUARD_OUTDATED", "the engine serves the agent degraded")

	r := g.upgrade(t, g.d.URL, "", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, setupcode.UpgradeLine(older, latest))
	require.Contains(t, r.stdout, fmt.Sprintf("Missing versions: %s.", missing))
	require.Contains(t, r.stderr, fmt.Sprintf("guard upgraded from version %d to %d (applied %s)", older, latest, missing))
	require.NotContains(t, r.stdout+r.stderr, g.d.URL, "the admin connection string is never printed")
	require.Equal(t, latest, g.version(t))

	// The same running engine serves the agent now, and its credential
	// still logs in and writes through the guard.
	res := g.callTool(t, "list_runs")
	require.NotContains(t, res, "GUARD_OUTDATED")
	require.NotContains(t, res, `"isError":true`, res)
	require.Equal(t, guard.GuardOK, g.agentStatus(t).State)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, g.dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `UPDATE public.leads SET score = 1 WHERE id = 1`)
	code, ok := guard.CodeOf(err)
	require.True(t, ok, "the guard still records the agent's writes")
	require.Equal(t, guard.CodeIntentRequired, code)
}

func TestUpgradeIsANoOpOnACurrentGuard(t *testing.T) {
	t.Parallel()
	g := newOlderGuard(t, 0)
	r := g.upgrade(t, "", "")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, fmt.Sprintf("the guard is up to date (version %d); nothing to upgrade", guard.LatestVersion()))
	require.NotContains(t, r.stderr, "Admin connection string", "a current guard needs no admin connection string")
	require.Empty(t, r.stdout)
}

func TestUpgradeDryRunChangesNothing(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	r := g.upgrade(t, g.d.URL, "", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, setupcode.UpgradeLine(latest-1, latest))
	require.Contains(t, r.stdout, fmt.Sprintf("INSERT INTO basalt_meta.schema_version (version) VALUES (%d);", latest))
	require.NotContains(t, r.stdout, fmt.Sprintf("VALUES (%d);", latest-1), "only the missing migration")
	require.NotContains(t, r.stdout, "ROLE "+g.d.Names.Prefix+"_agent_bot", "no agent change")
	require.Contains(t, r.stderr, "dry run; nothing ran")
	require.Equal(t, latest-1, g.version(t))
}

// A database default of session_replication_role other than origin is a
// warning on stderr naming the fix; the plan still runs.
func TestUpgradeWarnsWhenReplicationRoleIsNotOrigin(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	g := newOlderGuard(t, guard.LatestVersion()-1)
	g.d.Exec(t, `DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET session_replication_role = replica', current_database()); END $$`)
	r := g.upgrade(t, g.d.URL, "", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "basalt: warning: the database default of session_replication_role is replica, not origin.")
	require.Contains(t, r.stderr, "RESET session_replication_role;")
	require.NotContains(t, r.stdout, "warning")
}

func TestUpgradeAsksBeforeRunning(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	r := g.upgrade(t, g.d.URL, "n\n")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "Run this? [y/N]")
	require.Contains(t, r.stderr, "upgrade canceled; nothing changed")
	require.Equal(t, latest-1, g.version(t))

	r = g.upgrade(t, g.d.URL, "y\n")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, latest, g.version(t))
}

func TestUpgradeRefusesAnotherDatabase(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	other := guardtest.New(t)
	r := g.upgrade(t, other.URL, "", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "but your admin connection string points at database")
	require.Contains(t, r.stderr, "nothing changed")
	require.NotContains(t, r.stderr, other.URL, "the admin connection string is never printed")
	require.Equal(t, latest-1, g.version(t))
	require.Equal(t, 0, installedVersion(t, other), "nothing was installed in the other database")
}

func TestUpgradeRefusesAGuardItCannotUpgrade(t *testing.T) {
	t.Parallel()
	t.Run("newer than this basalt", func(t *testing.T) {
		t.Parallel()
		g := newOlderGuard(t, 0)
		latest := guard.LatestVersion()
		g.d.Exec(t, fmt.Sprintf(`INSERT INTO basalt_meta.schema_version (version) VALUES (%d)`, latest+1))
		r := g.upgrade(t, g.d.URL, "", "--yes")
		require.Equal(t, exitError, r.code)
		require.Contains(t, r.stderr, fmt.Sprintf("the guard (version %d) is newer than this basalt (version %d)", latest+1, latest))
		require.NotContains(t, r.stderr, "Admin connection string")
	})
	t.Run("not installed", func(t *testing.T) {
		t.Parallel()
		g := newOlderGuard(t, 0)
		g.d.Exec(t, `DROP SCHEMA basalt_meta CASCADE`)
		r := g.upgrade(t, g.d.URL, "", "--yes")
		require.Equal(t, exitError, r.code)
		require.Contains(t, r.stderr, "the guard is not installed")
		require.Contains(t, r.stderr, "basalt init")
		require.Equal(t, 0, g.version(t))
	})
}

func TestUpgradeRefusesAGuardOperatedByTheAgent(t *testing.T) {
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	g := newOlderGuard(t, guard.LatestVersion()-1)
	g.writeConfig(t, "AGENT")
	r := g.upgrade(t, g.d.URL, "", "--yes")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "basalt init --remote --agent bot")
	require.NotContains(t, r.stderr, "Admin connection string")
	require.Equal(t, guard.LatestVersion()-1, g.version(t))
}

func TestUpgradeUsage(t *testing.T) {
	t.Parallel()
	r := cliCmd(t, runUpgrade, nil, "")
	require.Equal(t, exitUsage, r.code)
	require.Contains(t, r.stderr, "--agent is required")
}
