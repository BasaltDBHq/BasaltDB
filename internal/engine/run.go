package engine

import (
	"context"
	"crypto/rand"
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
	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/engine/upkeep"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/notify/telegram"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

const lockFileName = "engine.lock"

var errNoAgent = errors.New("no agent to serve: every configured agent was refused (see the errors above)")

// Instructions is the MCP initialize instruction text every agent sees,
// from the engine and from the shim while the engine is down.
const Instructions = "BasaltDB records every action you take on this database. " +
	"Start a run with run_start and an intent, read with query, and change data with write and an intent. " +
	"A write of 11 to 50 rows, or any DELETE, is held for the person's passkey approval: show them approval.personMessage verbatim (it has the approval link and the equivalent basalt command), then, in the same turn, repeat the write once with approvalId: it waits for their approval and applies it. " +
	"If that wait runs out (APPROVAL_REQUIRED again), do not wait again: end your turn and say you apply it once they tell you they approved. " +
	"Over 50 rows, DDL and functions outside the allowlist are refused. " +
	"To undo your own work, find the run with list_runs, check it with preview_revert and query, tell the person what you recommend, then call request_revert: show its personMessage, then call request_revert once with revertId to wait for their passkey; if that wait runs out, do not wait again. " +
	linkInstructions

// linkInstructions is the sentence CONTRACT.md (Showing links, What the agent
// is told) puts in the initialize instructions, unchanged.
const linkInstructions = "When you show the person a link from Basalt, put it on its own line exactly as Basalt gave it, " +
	"or as a Markdown link [label](url) with the label from links. Never put a link in a code block or inline code, " +
	"never split, wrap, shorten, encode or rewrite it, and put nothing after it on its line. " +
	"Show personMessage verbatim and keep its line breaks."

// Run serves every agent in cfg until ctx is done. It takes the engine lock
// in the socket directory, so one engine runs per machine. configPath is the
// absolute path cfg was read from, which the person's basalt commands name
// with --config unless it is the platform default.
func Run(ctx context.Context, cfg config.Config, configPath string, log *slog.Logger) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("the engine runs on Linux and macOS only (it needs peer credentials on Unix sockets)")
	}
	lock, err := server.AcquireLock(filepath.Join(cfg.SocketDir, lockFileName))
	if err != nil {
		return err
	}
	defer lock.Release()

	// Every configured agent's OS user, before any agent is skipped: the
	// person socket scopes a peer that runs an agent to that agent (SM-4),
	// served or not, so a skipped agent's user never looks like the person.
	agentUIDs, err := agentOSUIDs(cfg.Agents, lookupUID)
	if err != nil {
		return err
	}
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
	pagesCfg, err := cfg.Pages()
	if err != nil {
		return err
	}
	var site *pagesSite
	if pagesCfg.Addr != "" {
		site, err = listenPages(pagesCfg, log)
		if err != nil {
			return err
		}
		closers = append(closers, func() { _ = site.ln.Close() })
	}
	base, err := cfg.PagesBase()
	if err != nil {
		return err
	}
	env := agentEnv{cfg: cfg, configPath: configPath, pagesBase: base, stateDir: cfg.StateDirFor(runtime.GOOS), pins: statePins(cfg.StateDirFor(runtime.GOOS), log), tg: tg}
	if site != nil {
		env.pagesOrigin = site.origin
	}
	ev := openVault(cfg, env.stateDir, time.Now, log)
	env.vault = ev
	st := ev.status()
	log.Info("vault", "state", st.State, "engineId", st.EngineID, "fingerprint", st.Fingerprint)
	srv, err := startAgents(ctx, cfg, env, agentUIDs, newAgentRuntime, log)
	closers = append(closers, srv.closers...)
	if err != nil {
		return err
	}
	agents, ledgers, upkeeps := srv.agents, srv.ledgers, srv.upkeeps
	if site != nil {
		for _, svc := range srv.services {
			site.pages.Add(svc)
		}
	}
	if len(agents) == 0 {
		return errNoAgent
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for _, u := range upkeeps {
		wg.Go(func() { u.Run(ctx, upkeep.DefaultInterval) })
	}
	if ev.client != nil {
		wg.Go(func() { _ = ev.client.Run(ctx) })
	}
	if cfg.Service() {
		srv, ln, err := listenPerson(cfg, ledgers, agentUIDs, person.PagesDTO{PagesURL: base, LocalOrigin: env.pagesOrigin}, log)
		if err != nil {
			return err
		}
		wg.Go(func() { srv.Serve(ctx, ln) })
	}
	if site != nil {
		wg.Go(func() { site.serve(ctx, log) })
	}
	return New(log, agents).Serve(ctx)
}

// agentOSUIDs is the uid of every configured agent's OS user, by agent
// name. An OS user that does not resolve stops the engine: the person
// socket must never mistake an agent's user for the person (fail closed).
func agentOSUIDs(agents []config.Agent, lookup func(string) (uint32, error)) (map[string]uint32, error) {
	out := make(map[string]uint32, len(agents))
	for _, a := range agents {
		uid, err := lookup(a.OSUser)
		if err != nil {
			return nil, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out[a.Name] = uid
	}
	return out, nil
}

// runtimeFunc builds one agent's runtime (newAgentRuntime outside tests).
type runtimeFunc func(ctx context.Context, env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error)

// startedAgents are the agents the engine serves and what it closes.
type startedAgents struct {
	agents   []Agent
	ledgers  map[string]person.Ledger
	upkeeps  []*upkeep.Upkeep
	services []*agent.Service
	closers  []func()
}

// startAgents builds each agent's runtime. An agent whose guard is missing
// or outdated is still served, degraded: status only, until the person
// installs or upgrades it (agent.Service.Admit). Every configured agent's OS
// user is in uids, which the person socket scopes by.
func startAgents(ctx context.Context, cfg config.Config, env agentEnv, uids map[string]uint32, newRT runtimeFunc, log *slog.Logger) (startedAgents, error) {
	out := startedAgents{ledgers: make(map[string]person.Ledger, len(cfg.Agents))}
	for _, a := range cfg.Agents {
		rt, err := newRT(ctx, env, a, log.With("agent", a.Name))
		if err != nil {
			return out, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out.closers = append(out.closers, rt.close)
		out.ledgers[a.Name] = rt.ledger
		out.upkeeps = append(out.upkeeps, rt.upkeep)
		out.services = append(out.services, rt.svc)
		out.agents = append(out.agents, Agent{
			Name:       a.Name,
			UID:        uids[a.Name],
			SocketPath: cfg.SocketPath(a.Name),
			Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: Instructions}, agent.Tools(rt.svc)...),
		})
	}
	return out, nil
}

// listenPerson opens the person socket of a service-mode engine (CONTRACT.md,
// The person socket): mode 0666 like the agent sockets, admitting only the
// recorded person uids.
func listenPerson(cfg config.Config, ledgers map[string]person.Ledger, agentUIDs map[string]uint32, pages person.PagesDTO, log *slog.Logger) (*person.Server, *net.UnixListener, error) {
	path := config.PersonSocketPath(cfg.SocketDir)
	ln, err := listenSocket(path)
	if err != nil {
		return nil, nil, fmt.Errorf("person socket: %w", err)
	}
	log.Info("serving the person socket", "socket", path, "personUids", cfg.PersonUIDs)
	srv := person.NewServer(person.Options{
		Allow: cfg.PersonUIDs, Agents: ledgers, AgentUIDs: agentUIDs, Pages: pages, PeerUID: peercred.UID, Log: log.With("component", "person"),
	})
	return srv, ln, nil
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
// listenPages binds the approval pages. A port it cannot bind stops the
// engine: without the pages, held writes would carry only the long link,
// which chat clients truncate. Run skips it when pagesAddr is "off".
func listenPages(p config.Pages, log *slog.Logger) (*pagesSite, error) {
	srv := pages.New(p.Origin, log.With("component", "pages"))
	ln, h, err := server.Listen(server.Options{}, "approval pages", p.Addr, srv.Handler())
	if err != nil {
		return nil, pagesPortError(p.Addr, err)
	}
	log.Info("serving approval pages", "addr", ln.Addr().String(), "origin", p.Origin)
	return &pagesSite{pages: srv, ln: ln, handler: h, origin: p.Origin}, nil
}

func pagesPortError(addr string, err error) error {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	return fmt.Errorf("%w: another process holds %s (an old `make serve-web`, or another engine): "+
		"find it with `lsof -nP -iTCP:%s -sTCP:LISTEN`, stop it and start the engine again "+
		`(or set "pagesAddr": "off" in engine.json to run without the pages)`, err, addr, port)
}

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
	// ledger serves the person socket on the agent's credential.
	ledger person.Ledger
	close  func()
}

// agentEnv is what every agent's runtime shares.
type agentEnv struct {
	cfg         config.Config
	configPath  string
	pagesBase   string
	pagesOrigin string
	stateDir    string
	pins        upkeep.Pins
	tg          *telegram.Notifier
	// vault reports the Vault connection in every agent's status.
	vault agent.VaultReporter
}

func newAgentRuntime(ctx context.Context, env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error) {
	limits, err := sqlLimits(env.cfg.Limits)
	if err != nil {
		return agentRuntime{}, err
	}
	cmds, err := agent.NewCommands(a.Name, env.configPath, runtime.GOOS, a.InitArgs)
	if err != nil {
		return agentRuntime{}, err
	}
	if !env.cfg.Service() {
		cmds = cmds.Foreground()
	}
	url, err := config.ReadCredential(a.CredentialFile)
	if err != nil {
		return agentRuntime{}, err
	}
	pool, err := agentdb.NewPool(ctx, url, agentPoolConns)
	if err != nil {
		return agentRuntime{}, err
	}
	probe := agent.DBProbe{Q: pool, Migrations: guard.Migrations()}
	logGuard(ctx, probe, log)
	store := agentdb.NewStore(pool, limits, time.Now)
	blind := agent.NewBlindCache(func(ctx context.Context, tables []string) ([]string, error) {
		return guard.RLSBlindTables(ctx, pool, "", tables)
	})
	svc := agent.NewService(agent.Deps{
		Name:        a.Name,
		Reader:      agentdb.NewReader(pool, limits, time.Now),
		Store:       store,
		Reads:       store,
		Approvals:   store,
		Reverts:     store,
		Notifier:    agentNotifier(env.tg, pool.Config().ConnConfig.Database),
		PagesBase:   env.pagesBase,
		LinkBudget:  env.cfg.LinkBudgetOrDefault(),
		Commands:    cmds,
		PagesOrigin: env.pagesOrigin,
		Links:       linkSecrets(env.stateDir, a.Name, log),
		RLS:         blind,
		Log:         log,
		Now:         time.Now,
		OperatedBy:  env.cfg.OperatedBy,
		SameUser:    !env.cfg.Service(),
		Setup:       a.Setup,
		Probe:       probe,
		Vault:       env.vault,
	})
	return agentRuntime{
		svc:    svc,
		upkeep: upkeep.New(a.Name, buildinfo.Version, pool, log, time.Now).WithPins(env.pins).WithRLSCache(blind),
		ledger: person.NewDBLedger(pool, time.Now),
		close:  pool.Close,
	}, nil
}

// logGuard logs the agent's guard as the engine starts serving it. A guard
// that is missing or misses a breaking migration, or a database the engine
// cannot reach, does not stop the engine: the agent gets status and its
// problems, and the guard is read again on each call.
func logGuard(ctx context.Context, probe agent.DBProbe, log *slog.Logger) {
	st, err := probe.GuardStatus(ctx)
	switch {
	case err != nil:
		log.Error("cannot read the guard; only status works until the database answers", "err", err)
	case !st.Served():
		log.Error("the guard cannot serve this agent; only status works until it is installed or upgraded",
			"guard", st.State, "installed", st.Installed, "build", st.Build, "missingBreaking", st.MissingBreaking)
	case st.State == guard.GuardUpgradeAvailable:
		log.Warn("the guard misses non-breaking migrations; basalt upgrade adds them", "missingNonBreaking", st.MissingNonBreaking)
	}
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

// linkSecrets is agent's link-secret store, persisted in the state
// directory (CONTRACT.md, Link secrets) so short links survive a restart.
// A directory it cannot create, or a file it cannot read, is logged: the
// store then starts empty, and those links are issued again.
func linkSecrets(dir, agent string, log *slog.Logger) *links.Secrets {
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		log.Error("no state directory; short links last until the engine stops", "dir", dir, "err", err)
		return links.NewSecrets(time.Now, rand.Reader)
	}
	s, err := links.OpenSecrets(filepath.Join(dir, agent+linkSecretsSuffix), time.Now, rand.Reader)
	if err != nil {
		log.Error("link secrets unreadable; earlier short links stop working", "err", err)
	}
	return s
}

// linkSecretsSuffix names an agent's link-secret file in the state
// directory: <stateDir>/<agent>.links.json.
const linkSecretsSuffix = ".links.json"
