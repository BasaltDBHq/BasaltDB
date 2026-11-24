package app

import (
	"cmp"
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

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"

	"github.com/basaltdbhq/basaltdb/internal/links/out/secretfile"

	"github.com/basaltdbhq/basaltdb/internal/ledger/out/pinfile"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/lib/pidlock"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/httpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setuppage"
	"github.com/basaltdbhq/basaltdb/internal/status"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"
)

var errNoAgent = errors.New("no agent to serve: every configured agent was refused (see the errors above)")

// Instructions is the MCP initialize instruction text every agent sees,
// from the engine and from the shim while the engine is down.
const Instructions = "BasaltDB records every action you take on this database. " +
	"Call status at the start of a session, after the person says they fixed something, and when a call fails with UNAVAILABLE. " +
	"Start a run with run_start and an intent, read with query, and change data with write and an intent. " +
	"Every error and every result that needs action carries nextSteps: do them in order. Do the AGENT steps yourself; CALL_TOOL steps have their arguments filled in. " +
	"Show the person personMessage verbatim, and every PERSON step's command and link unchanged. " +
	"STOP means do not retry or work around it; END_TURN means end your turn and let the person act. " +
	"When status says operatedBy PERSON, never start, stop, restart or upgrade anything yourself. " +
	"Never split a write to avoid a hold, and never retry a refusal in a loop. " +
	"A write of 11 to 50 rows, or any DELETE, is held for the person's passkey approval: show them approval.personMessage verbatim (it has the approval link), then, in the same turn, repeat the write once with approvalId: it waits for their approval and applies it. " +
	"If that wait runs out (APPROVAL_REQUIRED again), do not wait again: end your turn and say you apply it once they tell you they approved. " +
	"Over 50 rows, DDL and functions outside the allowlist are refused. " +
	"To undo your own work, find the run with list_runs, check it with preview_revert and query, tell the person what you recommend, then call request_revert: show its personMessage, then call request_revert once with revertId to wait for their passkey; if that wait runs out, do not wait again. " +
	"A revert covers only your own work: your change, your run, or your own changes in a task you ran in (taskId), optionally narrowed with runs and tables. " +
	"For a task, tell the person they can include other agents' changes on the signing page; after they do, you see only status and totals (widened: true) and get no link, so do not ask what they added. " +
	"If they reject it, the wait returns REJECTED with their note: stop, and request it again only if they ask. " +
	"reissueLink on a widened revert resets it to your own work and the person's page stops working: use it only when the person asks for a new link. " +
	"You can never approve a write or sign a revert. " +
	updateInstructions + " " +
	adminInstructions + " " +
	docsInstructions + " " +
	linkInstructions

// updateInstructions is the sentence CONTRACT.md (Update notice) puts in the
// initialize instructions, unchanged.
const updateInstructions = "When a result carries a WARNING: or SECURITY UPDATE: notice or an update field, tell the person that a newer BasaltDB release is out and give them the upgrade command it names; " +
	"never upgrade BasaltDB yourself unless the person says yes."

// adminInstructions is the sentence CONTRACT.md (Agents and the admin
// credential, What the agent is told) puts in the initialize instructions,
// unchanged: the admin credential never reaches the agent.
const adminInstructions = "Never ask the person for, or accept, their database admin connection string or password: " +
	"to set up, repair or change your access, follow nextSteps or run basalt init (basalt init --remote on a computer the person cannot reach), and show the person the one link it prints; " +
	"they finish on that page. If the person pastes an admin password, tell them to change it now."

// docsInstructions is the one sentence that points an agent to the public
// docs (CONTRACT.md, What the agent is told). The .md form of each page is
// written for agents.
const docsInstructions = "For error codes and troubleshooting, read https://docs.basaltvault.app/llms.txt (each page is also Markdown at its path with .md in place of the trailing slash, e.g. https://docs.basaltvault.app/reference/errors.md)."

// linkInstructions is the sentence CONTRACT.md (Showing links, What the agent
// is told) puts in the initialize instructions, unchanged.
const linkInstructions = "When you show the person a link from Basalt, put it on its own line exactly as Basalt gave it, " +
	"or as a Markdown link [label](url) with the label from links. Never put a link in a code block or inline code, " +
	"never split, wrap, shorten, encode or rewrite it, and put nothing after it on its line. " +
	"Show personMessage verbatim and keep its line breaks."

// runWith is Run with the restart onto a new binary: when restart.Upgrade
// returns, the engine stops between calls, closes everything Run opened,
// releases its lock and returns ErrRestart.
func runWith(ctx context.Context, cfg config.Config, configPath string, log *slog.Logger, restart restartOptions) error {
	if runtime.GOOS != "linux" && runtime.GOOS != goosDarwin {
		return errors.New("the engine runs on Linux and macOS only (it needs peer credentials on Unix sockets)")
	}
	// A listener a waiting engine handed on is closed on any return before
	// the pages take it (httpserver.TakeHandedListener).
	handed := restart.PagesListener
	defer func() {
		if handed != nil {
			_ = handed.Close()
		}
	}()
	// Every configured agent's OS user, before any agent is skipped: the
	// person socket scopes a peer that runs an agent to that agent (SM-4),
	// served or not, so a skipped agent's user never looks like the person.
	agentUIDs, err := engine.AgentOSUIDs(cfg.Agents, lookupUID)
	if err != nil {
		return err
	}
	// Folders first: an update of the computer drops empty ones and resets
	// the rest to 0755, and the lock below makes the socket directory.
	if err := engine.EnsureOwnDirs(cfg, agentUIDs, os.Geteuid()); err != nil {
		return err
	}
	lock, err := pidlock.AcquireLock(engine.LockPath(cfg.SocketDir))
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := lock.WritePID(os.Getpid()); err != nil {
		// basalt status then shows the engine running without its pid.
		log.Warn("could not write the engine's pid to its lock file", "err", err)
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
	if cfg.DevLocalPages {
		log.Warn(config.DevLocalPagesWarning, "pagesUrl", cfg.PagesURL)
	}
	var site *pagesSite
	var jobs setuppage.SetupJobs
	rotated := setup.NewRotations()
	pagesLn := httpserver.TakeHandedListener(handed, pagesCfg.Addr, setup.PageAddr)
	handed = nil
	if pagesCfg.Addr != "" {
		jobs = setupJobs(cfg, configPath, pagesCfg.Origin, log, rotated.Changed)
		site, err = listenPages(pagesCfg, pagesLn, jobs, log)
		if err != nil {
			return err
		}
		closers = append(closers, func() { _ = site.ln.Close() })
	}
	base, err := cfg.PagesBase()
	if err != nil {
		return err
	}
	env := agentEnv{cfg: cfg, startedBy: engine.StartedByOrHand(restart.StartedBy), configPath: configPath, asRoot: os.Geteuid() == 0, pagesBase: base, stateDir: cfg.StateDirFor(runtime.GOOS), pins: statePins(cfg.StateDirFor(runtime.GOOS), log), rotated: rotated}
	// Plugins are verified now and started below, once the agents serve: a
	// plugin that fails never stops the engine. With no enabled entry
	// nothing is read or started.
	pluginLog := log.With("component", "plugins")
	pluginOpts := pluginOptions{
		Stderr: pluginDebugWriter(cfg, restart.PluginStderr, log), euid: plugin.EUID(),
		runs: pluginRuns(cfg, env.stateDir, plugin.EUID(), pluginLog), stateDir: env.stateDir,
	}
	keepsPlugins := plugin.KeepsEntries(cfg)
	if keepsPlugins {
		// A service engine, and an agent-operated one on the bot's computer,
		// keeps plugin entries of its own, added with request_plugin, and
		// runs them once approved (CONTRACT.md, Plugin approval in service
		// mode, Plugin approval through the portal).
		pluginOpts.kept = openKeptStore(cfg, env.stateDir, pluginLog)
	}
	plugins := newEnginePlugins(cfg, configPath, pluginOpts, pluginLog)
	if plugins == nil && (!cfg.Service() || pluginOpts.kept != nil) {
		// A same-user engine starts an entry approved while it runs
		// (pluginWatch), so it keeps its plugins with none enabled yet.
		plugins = newEnginePluginsFor(cfg, configPath, pluginOpts, pluginLog)
	}
	if plugins != nil {
		env.plugins = plugins
		env.deliverer = plugins.DeliverLinks
	}
	if keepsPlugins {
		env.requests = newPluginRequests(agentUIDs, plugin.Callers(cfg, uint32(os.Geteuid())))
	}
	portal := newPortalChecker(base, env.stateDir, log, time.Now)
	if portal != nil {
		env.portal = portal
	}
	if !cfg.UpdateCheckOn() || updatecheck.Disabled(os.Getenv) {
		log.Info("update check is off")
	} else if uc := (&updatecheck.Checker{Dir: env.stateDir, Current: buildinfo.Version}); uc.Current != updatecheck.DevVersion {
		env.update = uc
	}
	piiCfg := cfg.PIIOrDefault()
	piiLog := log.With("component", "pii")
	// A key file wider than 0600, or PII state the engine cannot open,
	// stops the engine (M51-1): it never serves without its dictionary.
	dict, err := openPII(env.stateDir, piiCfg, piiLog)
	if err != nil {
		return err
	}
	closers = append(closers, func() { _ = dict.Close() })
	env.dict = dict
	if site != nil {
		env.pagesOrigin = site.origin
		if jobs != nil {
			env.setupOrigin = site.origin
		}
	}
	relay := linksvc.NewRegistry(log.With("component", "vault"))
	// Link sessions through the Vault are answered by the pages API on the
	// portal's origin (CONTRACT.md, Vault channel, Frames), with no
	// listener: only the session reaches these handlers.
	var sessionPages *pageserver.Server
	var dispatch vault.Dispatcher
	// gate counts the agent calls, person requests and page sessions
	// running, so a restart onto an upgraded binary waits for them.
	gate := engine.NewCallGate()
	if cfg.VaultEnabled() {
		sessionPages = newPages(base, log.With("component", "vault-pages"))
		dispatch = gatedDispatcher{gate: gate, next: sessionDispatcher{sessionPages}}
	}
	ev := openVault(cfg, env.stateDir, time.Now, log, relay, dispatch)
	env.vault, env.receipts = ev, ev.Receipts()
	if ev.Keys != nil {
		env.keys = ev.Keys
	}
	env.handoff = wireHandoff(restart.Handoff)
	// A connect-only agent's setup that changes (the person confirmed its
	// database) has the engine stop between calls and serve its config
	// again, as for an upgraded binary.
	reload, reloading := make(chan struct{}, 1), make(chan struct{})
	env.reload = func() {
		select {
		case reload <- struct{}{}:
		default:
		}
	}
	restart.Upgrade = engine.UpgradeOrReload(restart.Upgrade, reload, reloading)
	if ev.Client != nil {
		env.relay, env.relayLinks = ev.Client, relay
	}
	st := ev.Status()
	log.Info("vault", "state", st.State, "engineId", st.EngineID, "fingerprint", st.Fingerprint)
	srv, err := startAgents(ctx, cfg, env, agentUIDs, newAgentRuntime, log)
	closers = append(closers, srv.closers...)
	if err != nil {
		return err
	}
	agents, upkeeps := srv.agents, srv.upkeeps
	for _, svc := range srv.services {
		if site != nil {
			site.pages.Add(svc)
		}
		if sessionPages != nil {
			sessionPages.Add(svc)
		}
	}
	if len(agents) == 0 {
		return errNoAgent
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	// An engine that has stayed up, however it was started, ends the story
	// of an earlier give-up: status stops reporting it.
	stable := time.AfterFunc(cmp.Or(restart.StableAfter, defaultStableAfter), func() {
		if err := os.Remove(filepath.Join(env.stateDir, engine.LastStopFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("could not remove the record of why the engine stopped", "err", err)
		}
	})
	defer stable.Stop()
	for _, u := range upkeeps {
		wg.Go(func() { u.Run(ctx, ledger.DefaultInterval) })
	}
	for _, run := range srv.runs {
		wg.Go(func() { run(ctx) })
	}
	// Each agent's ledger records its plugin changes before any plugin
	// starts; an entry whose record fails is not served to that agent. In
	// same-user mode the plugins then follow engine.json and the agents'
	// approvals while the engine runs (pluginWatch). The supervisor stops
	// the plugins within plugin.StopWait of ctx ending, before runWith
	// returns (and before a restart runs a new binary).
	wg.Go(func() {
		recordPluginEvents(ctx, cfg, configPath, plugins, srv.pluginLedgers, log.With("component", "plugins"))
		if plugins != nil {
			plugins.Serve(ctx, cfg, configPath, pluginLedgers(srv.pluginLedgers))
		}
	})
	scanner := pii.NewScanner(dict, srv.scans, pii.ScanOptions{
		RowsPerSecond: piiCfg.ScanRowsPerSecond, MaxMemoryBytes: piiCfg.MaxMemoryBytes(),
	}, piiLog)
	wg.Go(func() { scanner.Run(ctx) })
	if portal != nil {
		wg.Go(func() { portal.Run(ctx, status.Interval) })
	}
	if env.update != nil {
		wg.Go(func() {
			env.update.Run(ctx, func(err error) { log.Debug("update check failed", "err", err) })
		})
	}
	if ev.Client != nil {
		wg.Go(func() { _ = ev.Client.Run(ctx) })
		wg.Go(func() { relay.PruneEvery(ctx, pruneInterval) })
	}
	if keepsPlugins {
		if kept := openKeptPlugins(cfg, configPath, pluginOpts.kept, plugins, srv.kept, log.With("component", "plugins")); kept != nil {
			env.requests.SetKept(kept)
			// Ends a disable could not write are tried again now.
			wg.Go(func() { kept.EndDisabled(ctx) })
		}
	}
	if site != nil {
		wg.Go(func() { site.serve(ctx, log) })
	}
	err = engine.New(log, mcpLines{}, agents).WithGate(gate).WithRestart(restart.Restart).Serve(ctx)
	select {
	case <-reloading:
		if errors.Is(err, engine.ErrRestart) {
			return engine.ErrReload
		}
	default:
	}
	return err
}

// runtimeFunc builds one agent's runtime (newAgentRuntime outside tests).
type runtimeFunc func(ctx context.Context, env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error)

// startedAgents are the agents the engine serves and what it closes.
type startedAgents struct {
	agents   []engine.Agent
	upkeeps  []*ledger.Upkeep
	services []*Service
	scans    []pii.ScanSource
	// pluginLedgers are the agents' own ledgers, for their plugin events.
	pluginLedgers map[string]pluginLedger
	// kept are the agents as the plugin methods reach them.
	kept    map[string]keptAgent
	closers []func()
	// runs are the agents' own loops (a connect-only agent's collector).
	runs []func(context.Context)
}

// startAgents builds each agent's runtime. An agent whose guard is missing
// or outdated is still served, degraded: status only, until the person
// installs or upgrades it (agent.Service.Admit). Every configured agent's OS
// user is in uids, which the person socket scopes by.
func startAgents(ctx context.Context, cfg config.Config, env agentEnv, uids map[string]uint32, newRT runtimeFunc, log *slog.Logger) (startedAgents, error) {
	out := startedAgents{
		pluginLedgers: make(map[string]pluginLedger, len(cfg.Agents)),
		kept:          make(map[string]keptAgent, len(cfg.Agents)),
	}
	for _, a := range cfg.Agents {
		rt, err := newRT(ctx, env, a, log.With("agent", a.Name))
		if err != nil {
			return out, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out.closers = append(out.closers, rt.close)
		if rt.run != nil {
			out.runs = append(out.runs, rt.run)
		}
		if rt.svc == nil {
			// A connect-only agent waiting for its database: its tools
			// only, and nothing that reads a database.
			out.agents = append(out.agents, engine.Agent{
				Name: a.Name, UID: uids[a.Name], SocketPath: cfg.SocketPath(a.Name),
				Server: mcpServer{mcpserver.NewServer(env.serverInfo(nil), rt.tools...)},
			})
			continue
		}
		if rt.db != nil {
			out.pluginLedgers[a.Name] = pluginLedger{db: rt.db, admit: pluginAdmit(rt.svc)}
		}
		if rt.kept.db != nil {
			out.kept[a.Name] = rt.kept
		}
		out.upkeeps = append(out.upkeeps, rt.upkeep)
		out.services = append(out.services, rt.svc)
		if rt.scan.DB != nil {
			out.scans = append(out.scans, rt.scan)
		}
		out.agents = append(out.agents, engine.Agent{
			Name:       a.Name,
			UID:        uids[a.Name],
			SocketPath: cfg.SocketPath(a.Name),
			Server:     mcpServer{mcpserver.NewServer(env.serverInfo(rt.svc.UpdateNotice), AgentTools(rt.svc)...).WithMethods(env.requests.uploadMethods(a.Name, rt.svc.PluginUploadsServed))},
		})
	}
	return out, nil
}

// serverInfo is what an agent's MCP server says of itself, with notice as
// its update notice (nil for none). The hello answer carries who operates
// the engine and its local page origin, so basalt mcp knows which links it
// may open in the browser (CONTRACT.md, Auto-open).
func (env agentEnv) serverInfo(notice func() string) mcpserver.Info {
	operatedBy := mcpcontract.OperatedByPerson
	if env.cfg.AgentOperated() {
		operatedBy = mcpcontract.OperatedByAgent
	}
	return mcpserver.Info{
		Name: "basalt", Version: buildinfo.Version, Instructions: Instructions, Notice: notice, OnPanic: env.onPanic,
		OperatedBy: operatedBy, PagesOrigin: env.pagesOrigin,
	}
}

// pagesSite is the bound local pages listener (CONTRACT.md, Local pages).
type pagesSite struct {
	pages   *pageserver.Server
	ln      net.Listener
	handler http.Handler
	origin  string
}

// listenPages binds the local pages. Off, or an address it cannot bind (a
// page server still on the port): no pages, logged, and held writes carry
// the long link.
// listenPages binds the approval pages. A port it cannot bind stops the
// engine: without the pages, held writes would carry only the long link,
// which chat clients truncate. Run skips it when pagesAddr is "off".
func listenPages(p config.Pages, handed net.Listener, setup setuppage.SetupJobs, log *slog.Logger) (*pagesSite, error) {
	pagesLog := log.With("component", "pages")
	srv := newPages(p.Origin, pagesLog)
	if setup != nil {
		srv.MountSetup(setuppage.NewSetupHandlers(p.Origin, setup, pagesLog.With("component", "setup")))
	}
	if handed != nil {
		log.Info("serving approval pages", "addr", handed.Addr().String(), "origin", p.Origin)
		return &pagesSite{pages: srv, ln: handed, handler: httpserver.Wrap(p.Addr, handed, srv.Handler()), origin: p.Origin}, nil
	}
	ln, h, err := httpserver.Listen(httpserver.Options{}, "approval pages", p.Addr, srv.Handler())
	if err != nil {
		return nil, linksvc.PagesPortError(p.Addr, err)
	}
	log.Info("serving approval pages", "addr", ln.Addr().String(), "origin", p.Origin)
	return &pagesSite{pages: srv, ln: ln, handler: h, origin: p.Origin}, nil
}

// setupJobs is the setup page's UPDATE and REMOVE for a person-operated
// engine on its own OS user at the local setup origin (CONTRACT.md, The
// local setup page), or nil: an agent-operated engine never takes the
// admin connection string, nor does an engine run as root, which reads
// its agents' files by other rules.
func setupJobs(cfg config.Config, configPath, origin string, log *slog.Logger, rotated func(agent, password string)) setuppage.SetupJobs {
	if cfg.AgentOperated() || os.Geteuid() == 0 || origin != setup.PageOrigin {
		return nil
	}
	jobs, err := newLocalSetup(localsetup.Options{ConfigPath: configPath, Origin: origin, Configured: true, CredentialChanged: rotated})
	if err != nil {
		log.Warn("the setup page cannot update or remove agents", "err", err)
		return nil
	}
	return jobs
}

func (s *pagesSite) serve(ctx context.Context, log *slog.Logger) {
	hs := &http.Server{Handler: s.handler, ReadHeaderTimeout: linksvc.PagesHeaderTimeout}
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
	svc    *Service
	upkeep *ledger.Upkeep
	// scan is what the engine's PII scan reads for this agent.
	scan pii.ScanSource
	// db is the agent's own connection pool, outside any tool call.
	db guard.Querier
	// kept is how the person socket's plugin methods reach the agent.
	kept  keptAgent
	close func()
	// tools serve a connect-only agent waiting for its database (svc is
	// nil then), and run is its collect loop.
	tools []mcpserver.Tool
	run   func(context.Context)
}

// agentEnv is what every agent's runtime shares.
type agentEnv struct {
	cfg         config.Config
	startedBy   string // why this engine started (restartOptions.StartedBy)
	configPath  string
	pagesBase   string
	pagesOrigin string
	// setupOrigin is the setup page's origin when the engine serves its
	// UPDATE and REMOVE (setupJobs), else empty.
	setupOrigin string
	stateDir    string
	pins        ledger.Pins
	// rotated takes each agent's password setter, for the setup page's
	// REPAIR.
	rotated *setup.Rotations
	// vault reports the Vault connection in every agent's status.
	vault status.VaultReporter
	// portal reports the daily portal check in every agent's status; nil
	// without a portal in the config.
	portal status.PortalReporter
	// plugins reports the plugin entries listed for each agent in its
	// status; nil when no plugin is enabled.
	plugins status.PluginReporter
	// deliverer gives each agent where its approval notices go, for the
	// approval.deliver plugins; nil when the engine keeps no plugins.
	deliverer func(name string) linksvc.LinkDeliverer
	// requests serve request_plugin on a service engine, once its
	// engine-kept plugins are open; nil on a same-user engine.
	requests *pluginRequests
	// update is the daily newer-release check; nil when it is off.
	update *updatecheck.Checker
	// receipts signs the receipt of every relayed signature; nil when the
	// engine key file is refused (KEY_ERROR).
	receipts linksvc.ReceiptSigner
	// relay and relayLinks are set when the engine dials out to the Vault:
	// each agent registers its portal short links there.
	relay      *vault.Client
	relayLinks *linksvc.Registry
	// dict is the engine's PII dictionary, shared by every agent.
	dict *corepii.FuseDictionary
	// asRoot: the engine runs as root; it then
	// reaches each agent's files through openRootFiles.
	asRoot bool
	// keys sign a connect-only agent's collect requests; nil when the key
	// file is refused.
	keys handoff.Signer
	// handoff reaches the connect service and the collected database.
	handoff handoffOptions
	// reload has the engine serve its config again.
	reload func()
}

// commands are agent a's next-step commands: a foreground engine's when it
// is no service, and the setup page's UPDATE link for a when the engine
// serves the setup jobs (setupOrigin).
func (env agentEnv) commands(a config.Agent) (guidance.Commands, error) {
	cmds, err := newCommands(a.Name, env.configPath, runtime.GOOS, AgentServiceManager())
	if err != nil {
		return guidance.Commands{}, err
	}
	if !env.cfg.Service() {
		cmds = cmds.Foreground()
	}
	if env.setupOrigin != "" {
		if link, err := localsetup.Link(env.setupOrigin, localsetup.Job{Job: localsetup.JobUpdate, Agent: a.Name, OSUser: a.OSUser}); err == nil {
			cmds = cmds.UpdateLink(link)
		}
		// The setup page's REMOVE deletes engine.json with the last agent.
		cmds = cmds.Removed(setup.ConfigGone(env.configPath))
	}
	return cmds, nil
}

func newAgentRuntime(ctx context.Context, env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error) {
	limits, err := sqlLimits(env.cfg.Limits)
	if err != nil {
		return agentRuntime{}, err
	}
	cmds, err := env.commands(a)
	if err != nil {
		return agentRuntime{}, err
	}
	// One store per agent (CONTRACT.md, Stores); the config refuses any
	// kind but POSTGRES, the only adapter there is.
	if a.Store.Kind != config.StorePostgres {
		return agentRuntime{}, fmt.Errorf("agent %s: store kind %q is not served", a.Name, a.Store.Kind)
	}
	waiting, err := connectOnlyAgent(env, a, log)
	switch {
	case err != nil:
		return agentRuntime{}, fmt.Errorf("agent %s: %w", a.Name, err)
	case waiting:
		return newConnectOnlyRuntime(env, a, log)
	case a.Setup != nil && a.Setup.AwaitingAddress:
		// connectOnlyAgent finished a confirmation the engine stopped in.
		s := *a.Setup
		s.AwaitingAddress = false
		a.Setup = &s
	}
	files, err := agentFilesFor(env, a)
	if err != nil {
		return agentRuntime{}, err
	}
	url, err := files.ReadCredential()
	if err != nil {
		files.Close()
		return agentRuntime{}, err
	}
	pool, password, err := postgres.NewSwitchablePool(ctx, url, agentPoolConns)
	if err != nil {
		files.Close()
		return agentRuntime{}, err
	}
	if env.rotated != nil {
		env.rotated.Add(a.Name, func(pw string) {
			password.Set(pw)
			pool.Reset()
		})
	}
	finisher := &handoff.Finisher{
		ConfigPath: env.configPath, Agent: a.Name, CredFile: a.Store.CredentialFile, Files: files,
		Login: targetOf(pool.Config().ConnConfig), Parse: parseLogin, Password: password, Reset: pool.Reset,
		Connect: connectAgent, Log: log,
	}
	// Every read a tool call makes on the agent's connection is charged to
	// the call's result budget (CONTRACT.md, QUERY_TIMEOUT SIZE_LIMIT, one
	// budget per call). Reads outside a call (upkeep, the person's socket)
	// carry no budget and are not charged.
	budgeted := resultsize.Budgeted(pool)
	probe := postgres.Probe{Q: budgeted, Migrations: guard.Migrations(), Kept: ledger.KeptSetAside(env.pins, a.Name, log)}
	// The guard is logged once the engine serves, never before: a database
	// that is slow or drops packets must not keep the agent's socket down
	// (status.LogGuard).
	guardCtx, stopGuardLog := context.WithTimeout(ctx, guardLogTimeout)
	go func() {
		defer stopGuardLog()
		status.LogGuard(guardCtx, agentProbe{probe}, log)
	}()
	// The agent's classification map, and the values of IDENTIFIER columns
	// it reads added to the dictionary before they leave the engine: query
	// rows in the service, RETURNING rows inside the write's transaction.
	classes := pii.NewMap(log.With("component", "pii"))
	observer := pii.NewObserver(classes, env.dict)
	store := postgres.NewStore(budgeted, limits, time.Now).WithReturned(observer.Returned)
	secrets := linkSecrets(env.stateDir, a.Name, log)
	readRecord := func(ctx context.Context, id string) (*status.EngineRecord, error) {
		r, err := guard.EngineRecord(ctx, pool, id)
		return agentEngineRecord(r), postgres.MapError(err)
	}
	var relay linksvc.LinkRelay
	if env.relay != nil {
		relay = env.relay
	}
	if env.relayLinks != nil {
		env.relayLinks.Add(a.Name, secrets, env.dropLink)
	}
	blind := agentsvc.NewBlindCache(func(ctx context.Context, tables []string) ([]string, error) {
		return guard.RLSBlindTables(ctx, budgeted, "", tables)
	})
	var deliverer linksvc.LinkDeliverer
	if env.deliverer != nil {
		deliverer = env.deliverer(a.Name)
	}
	var requests plugin.PluginRequests
	if env.requests != nil {
		requests = env.requests
	}
	deps := AgentHostDeps()
	deps.Core.Name, deps.Core.Log, deps.Core.Now = a.Name, log, time.Now
	deps.Core.Store, deps.Core.Commands = store, cmds
	deps.Core.PagesBase, deps.Core.PagesOrigin, deps.Core.LinkBudget = env.pagesBase, env.pagesOrigin, env.cfg.LinkBudgetOrDefault()
	deps.Write.Store, deps.Write.RLS, deps.Write.PII = store, blind, observer.On(pgquerier.Neutralize(pool))
	deps.Approval.Store, deps.Approval.Columns = store, postgres.NewColumnOrder(budgeted)
	deps.Revert.Store = store
	deps.Delivery.Deliverer, deps.Delivery.Links, deps.Delivery.Relay, deps.Delivery.Receipts = deliverer, secrets, relay, env.receipts
	cc := pool.Config().ConnConfig
	deps.Status.Passkeys = store
	deps.Status.OperatedBy, deps.Status.DevLocalPages = env.cfg.OperatedBy, env.cfg.DevLocalPages
	deps.Status.ConnectBudget, deps.Status.SameUser = env.cfg.ConnectLinkBudget(), !env.cfg.Service()
	deps.Status.StartedBy, deps.Status.Setup, deps.Status.Probe = env.startedBy, a.Setup, agentProbe{probe}
	deps.Status.Vault, deps.Status.Portal, deps.Status.Plugins = env.vault, env.portal, env.plugins
	deps.Status.CrashDirs = status.CrashDirs(env.stateDir)
	deps.Status.Access = func(ctx context.Context) (status.CatalogAccess, error) { return agentAccess(ctx, pool) }
	deps.Status.Update, deps.Status.EngineRecord, deps.Status.Trust = agentUpdate(env.updateNotice()), readRecord, trustOf(pool)
	deps.Status.Database = handoff.ConnectDatabaseName(cc.Host, cc.Port, cc.Database)
	deps.Status.Finisher = finisher
	deps.Describe.Catalog = agentCatalog{postgres.NewCatalog(budgeted, limits, pool.Config().ConnConfig.Database).WithHost(pool.Config().ConnConfig.Host)}
	deps.Describe.Classes = pii.StoreClasses{BoundMap: classes.On(pgquerier.Neutralize(pool)), Store: storeErrors{}}
	// The plugin approval routes read and relay on the agent's own
	// credential, as the approval routes do.
	deps.Plugin.Approvals, deps.Plugin.Requests = store, requests
	svc := NewService(deps)
	repin := newRepin(env, a, pool.Config().ConnConfig, log)
	return agentRuntime{
		svc: svc,
		run: repin,
		upkeep: ledger.New(a.Name, buildinfo.Version, postgres.NewUpkeep(pool), log, time.Now).WithPins(env.pins).WithRLSCache(blind).
			WithOperatedBy(env.cfg.OperatedBy).WithGate(svc.AdmitTick).
			WithPII(pii.NewWatch(a.Name, classes, pgquerier.Neutralize(pool), log.With("component", "pii"))),
		scan: pii.ScanSource{Agent: a.Name, DB: pgquerier.Neutralize(pool), ReadOnly: pgquerier.ReadOnlyTx(pool), Classes: classes, Limits: limits},
		db:   pool,
		kept: keptAgent{
			db: pool, host: pool.Config().ConnConfig.Host, port: pool.Config().ConnConfig.Port,
			database: pool.Config().ConnConfig.Database, role: pool.Config().ConnConfig.User,
		},
		close: func() {
			stopGuardLog()
			pool.Close()
			files.Close()
		},
	}, nil
}

// guardLogTimeout bounds the guard read status.LogGuard makes as an agent starts.
const guardLogTimeout = 15 * time.Second

// agentFilesFor is how the engine reaches agent a's files: by path, or,
// started as root, through directories opened without
// following a link, from the computed credential path only (rootFiles).
func agentFilesFor(env agentEnv, a config.Agent) (handoff.AgentFiles, error) {
	if !env.asRoot {
		return handoff.PathFiles{ConfigPath: env.configPath, CredFile: a.Store.CredentialFile}, nil
	}
	return openRootFiles(env.configPath, a.Name, a.Store.CredentialFile)
}

// statePins keeps verified chain heads in dir. When dir cannot be created
// the engine still serves, pinning in memory only, and says so: a rewrite
// made while it is stopped is then caught only by the full check on start.
func statePins(dir string, log *slog.Logger) ledger.Pins {
	if err := os.MkdirAll(dir, engine.StateDirMode); err != nil {
		log.Error("no state directory; ledger chain heads are pinned in memory only", "dir", dir, "err", err)
		return &chainpin.Memory{}
	}
	return pinfile.File{Dir: dir}
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
	if err := os.MkdirAll(dir, engine.StateDirMode); err != nil {
		log.Error("no state directory; short links last until the engine stops", "dir", dir, "err", err)
		return links.NewSecrets(time.Now, rand.Reader)
	}
	s, err := secretfile.Open(filepath.Join(dir, agent+linkSecretsSuffix), time.Now, rand.Reader)
	if err != nil {
		log.Error("link secrets unreadable; earlier short links stop working", "err", err)
	}
	return s
}

// linkSecretsSuffix names an agent's link-secret file in the state
// directory: <stateDir>/<agent>.links.json.
const linkSecretsSuffix = ".links.json"

// dropLink ends what a dropped link has: its token at the Vault.
func (env agentEnv) dropLink(token channel.LinkToken) {
	if env.relay != nil {
		env.relay.Unregister(token)
	}
}

// updateNotice is the cached newer release, or nil when the check is off.
func (env agentEnv) updateNotice() func() *updatecheck.Notice {
	if env.update == nil {
		return nil
	}
	return env.update.Cached
}
