package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/upkeep"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/notify/telegram"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

const lockFileName = "engine.lock"

// instructions is the MCP initialize instruction text every agent sees.
const instructions = "BasaltDB records every action you take on this database. " +
	"Start a run with run_start and an intent, read with query, and change data with write and an intent. " +
	"A write of 11 to 50 rows, or any DELETE, is held for the person's passkey approval: give them the approvalUrl, then repeat the write with approvalId. " +
	"Over 50 rows, DDL and functions outside the allowlist are refused."

// Run serves every agent in cfg until ctx is done. It takes the engine lock
// in the socket directory, so one engine runs per machine.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("the engine runs on Linux and macOS only (it needs peer credentials on Unix sockets)")
	}
	lock, err := server.AcquireLock(filepath.Join(cfg.SocketDir, lockFileName))
	if err != nil {
		return err
	}
	defer lock.Release()

	agents := make([]Agent, 0, len(cfg.Agents))
	upkeeps := make([]*upkeep.Upkeep, 0, len(cfg.Agents))
	pins := statePins(cfg.StateDirFor(runtime.GOOS), log)
	tg, err := newTelegram(cfg.Notify)
	if err != nil {
		return err
	}
	var closers []func()
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	for _, a := range cfg.Agents {
		uid, err := lookupUID(a.OSUser)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		rt, err := newAgentRuntime(ctx, cfg, a, pins, tg, log.With("agent", a.Name))
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		closers = append(closers, rt.close)
		upkeeps = append(upkeeps, rt.upkeep)
		agents = append(agents, Agent{
			Name:       a.Name,
			UID:        uid,
			SocketPath: cfg.SocketPath(a.Name),
			Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: instructions}, rt.tools...),
		})
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for _, u := range upkeeps {
		wg.Go(func() { u.Run(ctx, upkeep.DefaultInterval) })
	}
	return New(log, agents).Serve(ctx)
}

// agentPoolConns bounds each agent's connections to its database.
const agentPoolConns = 4

// agentRuntime is what the engine holds for one agent: its tools, its
// timer, and the lazy connection pool on its own credential they share.
type agentRuntime struct {
	tools  []mcp.Tool
	upkeep *upkeep.Upkeep
	close  func()
}

func newAgentRuntime(ctx context.Context, cfg config.Config, a config.Agent, pins upkeep.Pins, tg *telegram.Notifier, log *slog.Logger) (agentRuntime, error) {
	limits, err := sqlLimits(cfg.Limits)
	if err != nil {
		return agentRuntime{}, err
	}
	url, err := config.ReadCredential(a.CredentialFile)
	if err != nil {
		return agentRuntime{}, err
	}
	pool, err := agentdb.NewPool(ctx, url, agentPoolConns)
	if err != nil {
		return agentRuntime{}, err
	}
	store := agentdb.NewStore(pool, limits, time.Now)
	svc := agent.NewService(agent.Deps{
		Name:         a.Name,
		Reader:       agentdb.NewReader(pool, limits, time.Now),
		Store:        store,
		Reads:        store,
		Approvals:    store,
		Reverts:      store,
		Notifier:     agentNotifier(tg, pool.Config().ConnConfig.Database),
		ApprovalPage: cfg.ApprovalPage,
		Log:          log,
		Now:          time.Now,
	})
	return agentRuntime{
		tools:  agent.Tools(svc),
		upkeep: upkeep.New(a.Name, buildinfo.Version, pool, log, time.Now).WithPins(pins),
		close:  pool.Close,
	}, nil
}

// stateDirMode keeps the engine's state to its own OS user.
const stateDirMode = 0o700

// statePins keeps verified chain heads in dir. When dir cannot be created
// the engine still serves, pinning in memory only, and says so: a rewrite
// made while it is stopped is then caught only by the full check on start.
func statePins(dir string, log *slog.Logger) upkeep.Pins {
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		log.Error("no state directory; ledger chain heads are pinned in memory only", "dir", dir, "err", err)
		return &chainpin.Memory{}
	}
	return chainpin.File{Dir: dir}
}

// sqlLimits applies the configured limits over the defaults.
func sqlLimits(l config.Limits) (sqlguard.Limits, error) {
	out := sqlguard.DefaultLimits()
	if l.StatementTimeoutMs > 0 {
		out.StatementTimeout = l.StatementTimeout()
	}
	if l.ReadRowLimit > 0 {
		out.ReadRowLimit = l.ReadRowLimit
	}
	if err := out.Validate(); err != nil {
		return sqlguard.Limits{}, fmt.Errorf("limits: %w", err)
	}
	return out, nil
}

func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("os user %q: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("os user %q has uid %q: %w", name, u.Uid, err)
	}
	return uint32(uid), nil
}
