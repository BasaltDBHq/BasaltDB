package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
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
	"A write of 11 to 50 rows, or any DELETE, is held for the person's passkey approval: show them approval.personMessage verbatim (it has the approval link and the equivalent basalt command), then repeat the write with approvalId, which waits for their approval and applies it. " +
	"Over 50 rows, DDL and functions outside the allowlist are refused."

// Run serves every agent in cfg until ctx is done. It takes the engine lock
// in the socket directory, so one engine runs per machine. configArg is the
// --config argument the person's basalt commands need to find cfg (empty
// for the default path); held writes name it in the commands they give.
func Run(ctx context.Context, cfg config.Config, configArg string, log *slog.Logger) error {
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
	site := listenPages(cfg, log)
	if site != nil {
		closers = append(closers, func() { _ = site.ln.Close() })
	}
	env := agentEnv{cfg: cfg, configArg: configArg, pins: statePins(cfg.StateDirFor(runtime.GOOS), log), tg: tg}
	if site != nil {
		env.pagesOrigin = site.origin
	}
	for _, a := range cfg.Agents {
		uid, err := lookupUID(a.OSUser)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		rt, err := newAgentRuntime(ctx, env, a, log.With("agent", a.Name))
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.Name, err)
		}
		closers = append(closers, rt.close)
		upkeeps = append(upkeeps, rt.upkeep)
		if site != nil {
			site.pages.Add(rt.svc)
		}
		agents = append(agents, Agent{
			Name:       a.Name,
			UID:        uid,
			SocketPath: cfg.SocketPath(a.Name),
			Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: instructions}, agent.Tools(rt.svc)...),
		})
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for _, u := range upkeeps {
		wg.Go(func() { u.Run(ctx, upkeep.DefaultInterval) })
	}
	if site != nil {
		wg.Go(func() { site.serve(ctx, log) })
	}
	return New(log, agents).Serve(ctx)
}

// pagesSite is the bound local pages listener (CONTRACT.md, Local pages).
type pagesSite struct {
	pages   *pages.Server
	ln      net.Listener
	handler http.Handler
	origin  string
}

// pagesHeaderTimeout bounds a page request's headers (slowloris).
const pagesHeaderTimeout = 10 * time.Second

// listenPages binds the local pages. Off, or an address it cannot bind (a
// page server still on the port): no pages, logged, and held writes carry
// the long link.
func listenPages(cfg config.Config, log *slog.Logger) *pagesSite {
	p, err := cfg.Pages()
	if err != nil {
		log.Error("approval pages not served", "err", err)
		return nil
	}
	if p.Addr == "" {
		return nil
	}
	srv := pages.New(p.Origin, log.With("component", "pages"))
	ln, h, err := server.Listen(server.Options{}, "approval pages", p.Addr, srv.Handler())
	if err != nil {
		log.Error("approval pages not served; held writes carry the long link", "addr", p.Addr, "err", err)
		return nil
	}
	log.Info("serving approval pages", "addr", ln.Addr().String(), "origin", p.Origin)
	return &pagesSite{pages: srv, ln: ln, handler: h, origin: p.Origin}
}

// serve answers page requests until ctx is done.
func (s *pagesSite) serve(ctx context.Context, log *slog.Logger) {
	hs := &http.Server{Handler: s.handler, ReadHeaderTimeout: pagesHeaderTimeout}
	go func() {
		<-ctx.Done()
		_ = hs.Shutdown(context.WithoutCancel(ctx))
	}()
	if err := hs.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("approval pages stopped", "err", err)
	}
}

// agentPoolConns bounds each agent's connections to its database.
const agentPoolConns = 4

// agentRuntime is what the engine holds for one agent: its service, its
// timer, and the lazy connection pool on its own credential they share.
type agentRuntime struct {
	svc    *agent.Service
	upkeep *upkeep.Upkeep
	close  func()
}

// agentEnv is what every agent's runtime shares.
type agentEnv struct {
	cfg         config.Config
	configArg   string
	pagesOrigin string
	pins        upkeep.Pins
	tg          *telegram.Notifier
}

// cliFlags select agent in the person's basalt commands.
func cliFlags(agent, configArg string) string {
	flags := "--agent " + agent
	if configArg == "" {
		return flags
	}
	return flags + " " + configArg
}

func newAgentRuntime(ctx context.Context, env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error) {
	limits, err := sqlLimits(env.cfg.Limits)
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
		Notifier:     agentNotifier(env.tg, pool.Config().ConnConfig.Database),
		ApprovalPage: env.cfg.ApprovalPage,
		CLIFlags:     cliFlags(a.Name, env.configArg),
		PagesOrigin:  env.pagesOrigin,
		Log:          log,
		Now:          time.Now,
	})
	return agentRuntime{
		svc:    svc,
		upkeep: upkeep.New(a.Name, buildinfo.Version, pool, log, time.Now).WithPins(env.pins),
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
