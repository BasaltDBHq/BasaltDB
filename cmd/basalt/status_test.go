//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

func (g olderGuard) status(t *testing.T, args ...string) result {
	t.Helper()
	return cliCmd(t, runStatus, nil, "", append([]string{"--config", g.configPath}, args...)...)
}

// requireNoSecret checks basalt status output for the agent's password,
// its connection string, the credential file's path and contents, and
// the admin's.
func (g olderGuard) requireNoSecret(t *testing.T, out string) {
	t.Helper()
	u, err := url.Parse(g.dsn)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	require.NotEmpty(t, pw)
	require.NotContains(t, out, pw, "the agent's password")
	require.NotContains(t, out, "postgres://", "a connection string")
	require.NotContains(t, out, g.credFile, "the credential file's path")
	require.NotContains(t, out, filepath.Base(g.credFile), "the credential file's name")
	admin, err := url.Parse(g.d.URL)
	require.NoError(t, err)
	// The test server's admin password may be a plain word ("basalt"), so
	// look for it as user info.
	adminPW, _ := admin.User.Password()
	require.NotContains(t, out, ":"+adminPW+"@", "the admin's password")
}

func TestStatusShowsAnOutdatedGuardAndTheUpgradeCommand(t *testing.T) {
	t.Parallel()
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	upgrade := "basalt upgrade --agent bot --config " + g.configPath

	r := g.status(t, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	g.requireNoSecret(t, r.stdout+r.stderr)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, "bot", out["agent"])
	require.Equal(t, g.configPath, out["configPath"])
	require.Equal(t, g.socketDir, out["socketDir"])
	require.Equal(t, filepath.Join(filepath.Dir(g.configPath), "state"), out["stateDir"])
	require.Equal(t, "PERSON", out["operatedBy"])
	require.Equal(t, false, out["ready"])
	require.Equal(t, map[string]any{"reachable": false, "build": out["engine"].(map[string]any)["build"]}, out["engine"],
		"no pid or OS user while the engine is not running")
	gs := out["guard"].(map[string]any)
	require.Equal(t, guard.GuardOutdated, gs["state"])
	require.InDelta(t, latest-1, gs["installed"], 0)
	require.Equal(t, []any{float64(latest)}, gs["missingBreaking"])
	codes := map[string]map[string]any{}
	for _, p := range out["problems"].([]any) {
		pm := p.(map[string]any)
		codes[pm["code"].(string)] = pm
	}
	require.Contains(t, codes, "ENGINE_UNREACHABLE")
	require.Contains(t, codes, "GUARD_OUTDATED")
	step := codes["GUARD_OUTDATED"]["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, upgrade, step["command"])
	start := codes["ENGINE_UNREACHABLE"]["nextSteps"].([]any)[0].(map[string]any)
	require.Equal(t, "basalt engine --config "+g.configPath, start["command"])

	text := g.status(t)
	require.Equal(t, exitOK, text.code, text.stderr)
	g.requireNoSecret(t, text.stdout+text.stderr)
	require.Contains(t, text.stdout, "Config:       "+g.configPath)
	require.Contains(t, text.stdout, "Engine:       not running")
	require.Contains(t, text.stdout, "Agent bot: not ready")
	require.Contains(t, text.stdout, fmt.Sprintf("Guard:      version %d, this basalt has %d: upgrade required (missing %d)", latest-1, latest, latest))
	require.Contains(t, text.stdout, "Run: "+upgrade)

	// The command status gives fixes it.
	up := g.upgrade(t, g.d.URL, "", "--yes")
	require.Equal(t, exitOK, up.code, up.stderr)
	r = g.status(t, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, guard.GuardOK, out["guard"].(map[string]any)["state"])
}

func TestStatusPicksTheOnlyAgentAndRefusesAnUnknownOne(t *testing.T) {
	t.Parallel()
	g := newOlderGuard(t, 0)
	r := g.status(t, "--agent", "other")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, `agent "other" is not in `+g.configPath)
	r = g.status(t)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "Agent bot: not ready", "the engine is not running")
	require.Contains(t, r.stdout, "Passkeys:   none registered")
}

func TestStatusReportsACredentialFileItCannotReadWithoutItsPath(t *testing.T) {
	t.Parallel()
	g := newOlderGuard(t, 0)
	require.NoError(t, os.Remove(g.credFile))
	r := g.status(t)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "the credential of agent bot cannot be read")
	require.NotContains(t, r.stderr, g.credFile)
}

// fakeEngine is a service-mode engine's person socket answering STATUS
// and TARGET for bot from report and target.
func fakeEngine(t *testing.T, report agent.StatusReport, target person.TargetDTO) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bst")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "person.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	const personUID = 4242
	srv := person.NewServer(person.Options{
		Allow:   []uint32{personUID},
		PeerUID: func(*net.UnixConn) (uint32, error) { return personUID, nil },
		Log:     slog.New(slog.DiscardHandler),
		Info: map[string]person.AgentInfo{"bot": {
			Status: func(context.Context) (json.RawMessage, error) { return json.Marshal(report) },
			Target: target,
		}},
		Engine: person.EngineInfo{Engine: person.EngineDTO{PID: 77, OSUser: "basalt"}, SocketDir: "/run/basalt", StateDir: "/var/lib/basalt"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

// serviceCmd runs a command as the person on a service-mode machine whose
// engine answers on socket.
func serviceCmd(t *testing.T, cmd func(*cliIO, []string) int, socket string, env map[string]string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return env[k] })
	c.engine = engineAccess{unitInstalled: func() bool { return true }, personSocket: socket}
	code := cmd(c, args)
	return result{code, stdout.String(), stderr.String()}
}

func outdatedReport(t *testing.T, g olderGuard) agent.StatusReport {
	t.Helper()
	cmds, err := agent.NewCommands("bot", "", "", nil)
	require.NoError(t, err)
	r, err := agent.LocalStatus{
		Name: "bot", Commands: cmds, EngineRunning: true,
		Probe:    agent.DBProbe{Q: g.d.Admin, Migrations: guard.Migrations()},
		Passkeys: func(context.Context) ([]passkey.Credential, error) { return nil, nil },
		Log:      slog.New(slog.DiscardHandler), Now: time.Now,
	}.Report(context.Background())
	require.NoError(t, err)
	return r
}

func dbTarget(t *testing.T, dsn string) person.TargetDTO {
	t.Helper()
	pc, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	return person.TargetDTO(setupcode.ConnTarget(pc.Host, int(pc.Port), pc.Database, pc.User))
}

func TestStatusAndUpgradeGoThroughThePersonSocketInServiceMode(t *testing.T) {
	t.Parallel()
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	report := outdatedReport(t, g)
	require.Equal(t, guard.GuardOutdated, report.Guard.State)

	t.Run("status", func(t *testing.T) {
		t.Parallel()
		socket := fakeEngine(t, report, dbTarget(t, g.dsn))
		r := serviceCmd(t, runStatus, socket, nil, "--agent", "bot", "--json")
		require.Equal(t, exitOK, r.code, r.stderr)
		g.requireNoSecret(t, r.stdout)
		var out map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
		require.Equal(t, config.DefaultPath(runtime.GOOS), out["configPath"])
		require.Equal(t, "/run/basalt", out["socketDir"])
		require.Equal(t, "/var/lib/basalt", out["stateDir"])
		eng := out["engine"].(map[string]any)
		require.InDelta(t, 77, eng["pid"], 0)
		require.Equal(t, "basalt", eng["osUser"])
		require.Equal(t, true, eng["reachable"])

		text := serviceCmd(t, runStatus, socket, nil, "--agent", "bot")
		require.Contains(t, text.stdout, "Engine:       running (pid 77, OS user basalt)")
		require.Contains(t, text.stdout, "Run: basalt upgrade --agent bot")

		usage := serviceCmd(t, runStatus, socket, nil)
		require.Equal(t, exitUsage, usage.code)
		require.Contains(t, usage.stderr, "give --agent NAME")
	})
	t.Run("engine stopped", func(t *testing.T) {
		t.Parallel()
		r := serviceCmd(t, runStatus, filepath.Join(t.TempDir(), "person.sock"), nil, "--agent", "bot")
		require.Equal(t, exitError, r.code)
		require.Contains(t, r.stderr, "the engine is not running; start it with")
		require.NotContains(t, r.stderr, "permission denied")
	})
	t.Run("upgrade refuses another database", func(t *testing.T) {
		t.Parallel()
		socket := fakeEngine(t, report, person.TargetDTO{Host: "db.example.com", Port: 5432, Database: "app"})
		r := serviceCmd(t, runUpgrade, socket, map[string]string{envAdminURL: g.d.URL}, "--agent", "bot", "--yes")
		require.Equal(t, exitError, r.code)
		require.Contains(t, r.stderr, "bot connects to database app of db.example.com:5432")
		require.Equal(t, latest-1, g.version(t))
	})
}

func TestUpgradeThroughThePersonSocket(t *testing.T) {
	t.Parallel()
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	socket := fakeEngine(t, outdatedReport(t, g), dbTarget(t, g.dsn))
	r := serviceCmd(t, runUpgrade, socket, map[string]string{envAdminURL: g.d.URL}, "--agent", "bot", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, latest, g.version(t))
}

// An engine still running an older build judges the guard by its own
// migrations and says OK; this basalt has one more, and upgrade adds it.
func TestUpgradeJudgesTheGuardByThisBuildNotTheRunningEngines(t *testing.T) {
	t.Parallel()
	latest := guard.LatestVersion()
	g := newOlderGuard(t, latest-1)
	old := outdatedReport(t, g)
	installed := latest - 1
	old.Guard = agent.GuardStatus{State: guard.GuardOK, Installed: &installed, Build: latest - 1}
	old.Problems, old.Ready = nil, true
	socket := fakeEngine(t, old, dbTarget(t, g.dsn))
	r := serviceCmd(t, runUpgrade, socket, map[string]string{envAdminURL: g.d.URL}, "--agent", "bot", "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "nothing to upgrade")
	require.Contains(t, r.stdout, setupcode.UpgradeLine(latest-1, latest))
	require.Equal(t, latest, g.version(t))
}

// A credential file outside the default is saved in initArgs (AE-15): its
// path may appear as that flag in an init command, never on its own, and
// its contents never.
func TestStatusNamesANonDefaultCredentialFileOnlyAsTheSavedFlag(t *testing.T) {
	t.Parallel()
	g := newOlderGuard(t, 0)
	custom := filepath.Join(filepath.Dir(g.configPath), "custom-cred.url")
	require.NoError(t, os.Rename(g.credFile, custom))
	cfg, err := config.Load(g.configPath)
	require.NoError(t, err)
	cfg.Agents[0].CredentialFile = custom
	cfg.Agents[0].InitArgs = append(cfg.Agents[0].InitArgs, "--credential-file="+custom)
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(g.configPath, raw, 0o600))

	for _, args := range [][]string{{"--json"}, nil} {
		r := g.status(t, args...)
		require.Equal(t, exitOK, r.code, r.stderr)
		out := r.stdout + r.stderr
		g.requireNoSecret(t, out)
		require.Contains(t, out, "--credential-file="+custom, "NO_PASSKEY's init command carries the saved flag")
		require.Equal(t, strings.Count(out, custom), strings.Count(out, "--credential-file="+custom),
			"the path appears only as the saved flag")
	}
}

func TestStatusSaysUnknownForALockFileItCannotOpen(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root opens any file")
	}
	g := newOlderGuard(t, 0)
	require.NoError(t, os.MkdirAll(g.socketDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(g.socketDir, "engine.lock"), []byte("12\n"), 0o000))

	r := g.status(t, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	eng := out["engine"].(map[string]any)
	require.Equal(t, true, eng["unknown"])
	require.Equal(t, false, eng["reachable"])
	for _, p := range out["problems"].([]any) {
		require.NotEqual(t, "ENGINE_UNREACHABLE", p.(map[string]any)["code"], "not known to be down")
	}
	text := g.status(t)
	require.Contains(t, text.stdout, "Engine:       unknown (its lock file, owned by ")
	require.NotContains(t, text.stdout, "not running")
}

func TestWriteStatusShowsTheLedger(t *testing.T) {
	t.Parallel()
	s := statusOut{StatusReport: agent.StatusReport{
		Agent:  "bot",
		Ledger: &agent.LedgerStatus{Bytes: 5_242_880, ValuesKeptDays: 30, RecordsKeptDays: 365},
	}}
	var b strings.Builder
	writeStatus(&b, s)
	require.Contains(t, b.String(), "  Passkeys:   unknown\n  Ledger:     5.0 MB in basalt_meta; values kept 30 days, records 1 year\n")

	s.Ledger = nil
	b.Reset()
	writeStatus(&b, s)
	require.NotContains(t, b.String(), "Ledger:")
}

func TestByteWords(t *testing.T) {
	t.Parallel()
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 1536: "1.5 KB", 1 << 20: "1.0 MB", 1<<20 - 1: "1.0 MB", 1<<30 - 1: "1.0 GB", 5 << 30: "5.0 GB", 2048 << 30: "2048.0 GB"} {
		require.Equal(t, want, byteWords(n))
	}
}

func TestStatusConfigFallsBackToThePerUserConfigWhenNotRoot(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(config.DefaultPath(runtime.GOOS)); err == nil {
		t.Skip("a system engine config is installed on this machine")
	}
	h := newFakeHost(t)
	system := config.DefaultPath(runtime.GOOS)
	c := &cliIO{host: h}

	require.Equal(t, system, perUserConfigFallback(c, system), "no per-user config yet")

	user := filepath.Join(h.configDir, perUserDirName, "engine.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(user), 0o700))
	require.NoError(t, os.WriteFile(user, []byte("{}"), 0o600))
	require.Equal(t, user, perUserConfigFallback(c, system))

	h.euid = 0
	require.Equal(t, system, perUserConfigFallback(c, system), "root keeps the system path")
}
