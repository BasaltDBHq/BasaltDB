package engine

import (
	"context"
	"crypto/rand"
	"encoding/json"
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

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/engine/piidict"
	"github.com/basaltdbhq/basaltdb/internal/engine/portalcheck"
	"github.com/basaltdbhq/basaltdb/internal/engine/upkeep"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/store/postgres"
	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

const lockFileName = "engine.lock"

// LockPath is the engine's lock file in socket directory dir: held while
// the engine runs, with its pid (basalt status reads both).
func LockPath(dir string) string { return filepath.Join(dir, lockFileName) }

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
	"A write of 11 to 50 rows, or any DELETE, is held for the person's passkey approval: show them approval.personMessage verbatim (it has the approval link and the equivalent basalt command), then, in the same turn, repeat the write once with approvalId: it waits for their approval and applies it. " +
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
const adminInstructions = "Never ask the person for, or accept, their database admin connection string or password, " +
	"and never run basalt init without --remote yourself: to set up or change your access, follow nextSteps or run basalt init --remote " +
	"and give the person the setup code it prints. If the person pastes an admin password, tell them to change it now."

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

// Run serves every agent in cfg until ctx is done. It takes the engine lock
// in the socket directory, so one engine runs per machine. configPath is the
// absolute path cfg was read from, which the person's basalt commands name
// with --config unless it is the platform default.
func Run(ctx context.Context, cfg config.Config, configPath string, log *slog.Logger) error {
	return RunWith(ctx, cfg, configPath, log, RestartOptions{})
}

// RunWith is Run with the restart onto a new binary: when restart.Upgrade
// returns, the engine stops between calls, closes everything Run opened,
// releases its lock and returns ErrRestart.
func RunWith(ctx context.Context, cfg config.Config, configPath string, log *slog.Logger, restart RestartOptions) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("the engine runs on Linux and macOS only (it needs peer credentials on Unix sockets)")
	}
	lock, err := server.AcquireLock(LockPath(cfg.SocketDir))
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := lock.WritePID(os.Getpid()); err != nil {
		// basalt status then shows the engine running without its pid.
		log.Warn("could not write the engine's pid to its lock file", "err", err)
	}

	// Every configured agent's OS user, before any agent is skipped: the
	// person socket scopes a peer that runs an agent to that agent (SM-4),
	// served or not, so a skipped agent's user never looks like the person.
	agentUIDs, err := agentOSUIDs(cfg.Agents, lookupUID)
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
	if cfg.DevLocalPages {
		log.Warn(config.DevLocalPagesWarning, "pagesUrl", cfg.PagesURL)
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
	env := agentEnv{cfg: cfg, configPath: configPath, asRoot: os.Geteuid() == 0, pagesBase: base, stateDir: cfg.StateDirFor(runtime.GOOS), pins: statePins(cfg.StateDirFor(runtime.GOOS), log)}
	// Plugins are verified now and started below, once the agents serve: a
	// plugin that fails never stops the engine. With no enabled entry
	// nothing is read or started.
	plugins := newEnginePlugins(cfg, configPath, pluginOptions{
		Stderr: pluginDebugWriter(cfg, restart.PluginStderr, log), euid: engineEUID(),
	}, log.With("component", "plugins"))
	if plugins != nil {
		env.plugins = plugins
	}
	portal := newPortalChecker(base, env.stateDir, log, time.Now)
	if portal != nil {
		env.portal = portal
	}
	updateCheck := "ON"
	if !cfg.UpdateCheckOn() || updatecheck.Disabled(os.Getenv) {
		log.Info("update check is off")
		updateCheck = "OFF"
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
	}
	relay := newRelayLinks(log.With("component", "vault"))
	// Link sessions through the Vault are answered by the pages API on the
	// portal's origin (CONTRACT.md, Vault channel, Frames), with no
	// listener: only the session reaches these handlers.
	directAddr, err := cfg.Direct()
	if err != nil {
		return err
	}
	var sessionPages *pages.Server
	var dispatch vault.Dispatcher
	// gate counts the agent calls, person requests and page sessions
	// running, so a restart onto an upgraded binary waits for them.
	gate := newCallGate()
	if cfg.VaultEnabled() || directAddr != "" {
		sessionPages = pages.New(base, log.With("component", "vault-pages"))
		dispatch = gatedDispatcher{gate: gate, next: sessionPages}
	}
	tally := vault.NewTally()
	ev := openVault(cfg, env.stateDir, time.Now, log, relay, dispatch, tally)
	env.vault, env.receipts = ev, ev.receipts()
	if ev.client != nil {
		env.relay, env.relayLinks = ev.client, relay
	}
	var direct *directSite
	if directAddr != "" && ev.keys == nil {
		log.Error("directAddr is set but the engine key file is refused: no direct listener until it is fixed", "addr", directAddr)
	}
	if directAddr != "" && ev.keys != nil {
		env.records = newEngineRecords(ev.keys.EngineID(), time.Now, log.With("component", "direct"))
		client := ev.client
		env.direct = vault.NewDirect(vault.DirectOptions{
			Keys: ev.keys, Log: log.With("component", "direct"), SessionLinks: relay, Pages: dispatch, Tally: tally,
			Recheck: env.records.revoked,
			// A widen in a direct session ends the old token's sessions
			// through the Vault too, without unregistering it.
			OnRotate: func(old channel.LinkToken) {
				if client != nil {
					client.EndSessions(old)
				}
			},
		})
		relay.setDirect(env.direct)
		env.relayLinks = relay
		direct, err = listenDirect(directAddr)
		if err != nil {
			return err
		}
		closers = append(closers, func() { _ = direct.ln.Close() })
		log.Info("direct listener", "addr", directAddr)
	}
	st := ev.status()
	log.Info("vault", "state", st.State, "engineId", st.EngineID, "fingerprint", st.Fingerprint)
	srv, err := startAgents(ctx, cfg, env, agentUIDs, newAgentRuntime, log)
	closers = append(closers, srv.closers...)
	if err != nil {
		return err
	}
	agents, ledgers, upkeeps := srv.agents, srv.ledgers, srv.upkeeps
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
	for _, u := range upkeeps {
		wg.Go(func() { u.Run(ctx, upkeep.DefaultInterval) })
	}
	if plugins != nil {
		// Stopped within plugin.StopWait of ctx ending, before RunWith
		// returns (and before a restart runs a new binary).
		wg.Go(func() { plugins.run(ctx) })
	}
	scanner := piidict.NewScanner(dict, srv.scans, piidict.ScanOptions{
		RowsPerSecond: piiCfg.ScanRowsPerSecond, MaxMemoryBytes: piiCfg.MaxMemoryBytes(),
	}, piiLog)
	wg.Go(func() { scanner.Run(ctx) })
	if portal != nil {
		wg.Go(func() { portal.Run(ctx, portalcheck.Interval) })
	}
	if env.update != nil {
		wg.Go(func() {
			env.update.Run(ctx, func(err error) { log.Debug("update check failed", "err", err) })
		})
	}
	if ev.client != nil {
		wg.Go(func() { _ = ev.client.Run(ctx) })
		wg.Go(func() { relay.pruneEvery(ctx, pruneInterval) })
	}
	if cfg.Service() {
		srv, ln, err := listenPerson(cfg, person.Options{
			Agents: ledgers, Info: srv.infos, AgentUIDs: agentUIDs,
			Engine: engineInfo(cfg.SocketDir, env.stateDir),
			Pages:  person.PagesDTO{PagesURL: base, LocalOrigin: env.pagesOrigin, UpdateCheck: updateCheck},
			Gate:   gate,
		}, log)
		if err != nil {
			return err
		}
		wg.Go(func() { srv.Serve(ctx, ln) })
	}
	if site != nil {
		wg.Go(func() { site.serve(ctx, log) })
	}
	if direct != nil {
		h := newDirectHandler(ctx, env.records, ev.keys.PublicKeySPKI(), env.direct, time.Now)
		wg.Go(func() { env.records.refresh(ctx) })
		wg.Go(func() { env.records.watchRevoked(ctx, env.direct, directRecheckEvery) })
		wg.Go(func() { direct.serve(ctx, h, env.direct, log) })
	}
	return New(log, agents).withGate(gate).WithRestart(restart).Serve(ctx)
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
	infos    map[string]person.AgentInfo
	upkeeps  []*upkeep.Upkeep
	services []*agent.Service
	scans    []piidict.ScanSource
	closers  []func()
}

// startAgents builds each agent's runtime. An agent whose guard is missing
// or outdated is still served, degraded: status only, until the person
// installs or upgrades it (agent.Service.Admit). Every configured agent's OS
// user is in uids, which the person socket scopes by.
func startAgents(ctx context.Context, cfg config.Config, env agentEnv, uids map[string]uint32, newRT runtimeFunc, log *slog.Logger) (startedAgents, error) {
	out := startedAgents{
		ledgers: make(map[string]person.Ledger, len(cfg.Agents)),
		infos:   make(map[string]person.AgentInfo, len(cfg.Agents)),
	}
	for _, a := range cfg.Agents {
		rt, err := newRT(ctx, env, a, log.With("agent", a.Name))
		if err != nil {
			return out, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		out.closers = append(out.closers, rt.close)
		out.ledgers[a.Name] = rt.ledger
		out.infos[a.Name] = rt.info
		out.upkeeps = append(out.upkeeps, rt.upkeep)
		out.services = append(out.services, rt.svc)
		if rt.scan.DB != nil {
			out.scans = append(out.scans, rt.scan)
		}
		out.agents = append(out.agents, Agent{
			Name:       a.Name,
			UID:        uids[a.Name],
			SocketPath: cfg.SocketPath(a.Name),
			Server:     mcp.NewServer(mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: Instructions, Notice: rt.svc.UpdateNotice, OnPanic: env.onPanic}, agent.Tools(rt.svc)...),
		})
	}
	return out, nil
}

// listenPerson opens the person socket of a service-mode engine (CONTRACT.md,
// The person socket): mode 0666 like the agent sockets, admitting only the
// recorded person uids.
func listenPerson(cfg config.Config, o person.Options, log *slog.Logger) (*person.Server, *net.UnixListener, error) {
	path := config.PersonSocketPath(cfg.SocketDir)
	ln, err := listenSocket(path)
	if err != nil {
		return nil, nil, fmt.Errorf("person socket: %w", err)
	}
	log.Info("serving the person socket", "socket", path, "personUids", cfg.PersonUIDs)
	o.Allow, o.PeerUID, o.Log = cfg.PersonUIDs, peercred.UID, log.With("component", "person")
	return person.NewServer(o), ln, nil
}

// engineInfo is what the person socket's STATUS says about this engine:
// its pid and OS user, and its socket and state directories.
func engineInfo(socketDir, stateDir string) person.EngineInfo {
	name := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return person.EngineInfo{Engine: person.EngineDTO{PID: os.Getpid(), OSUser: name}, SocketDir: socketDir, StateDir: stateDir}
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
	// info answers the person socket's STATUS and TARGET.
	info person.AgentInfo
	// scan is what the engine's PII scan reads for this agent.
	scan  piidict.ScanSource
	close func()
}

// agentEnv is what every agent's runtime shares.
type agentEnv struct {
	cfg         config.Config
	configPath  string
	pagesBase   string
	pagesOrigin string
	stateDir    string
	pins        upkeep.Pins
	// vault reports the Vault connection in every agent's status.
	vault agent.VaultReporter
	// portal reports the daily portal check in every agent's status; nil
	// without a portal in the config.
	portal agent.PortalReporter
	// plugins reports the plugin entries listed for each agent in its
	// status; nil when no plugin is enabled.
	plugins agent.PluginReporter
	// update is the daily newer-release check; nil when it is off.
	update *updatecheck.Checker
	// receipts signs the receipt of every relayed signature; nil when the
	// engine key file is refused (KEY_ERROR).
	receipts agent.ReceiptSigner
	// relay and relayLinks are set when the engine dials out to the Vault:
	// each agent registers its portal short links there.
	relay      *vault.Client
	relayLinks *relayLinks
	// direct serves the direct transport's sessions and records reads the
	// engine's record per agent database; both nil without directAddr.
	direct  *vault.Direct
	records *engineRecords
	// dict is the engine's PII dictionary, shared by every agent.
	dict *pii.FuseDictionary
	// asRoot: the engine runs as root (started without --user); it then
	// reaches each agent's files through openRootFiles.
	asRoot bool
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
	// One store per agent (CONTRACT.md, Stores); the config refuses any
	// kind but POSTGRES, the only adapter there is.
	if a.Store.Kind != config.StorePostgres {
		return agentRuntime{}, fmt.Errorf("agent %s: store kind %q is not served", a.Name, a.Store.Kind)
	}
	files, err := agentFilesFor(env, a)
	if err != nil {
		return agentRuntime{}, err
	}
	url, err := files.readCredential()
	if err != nil {
		files.close()
		return agentRuntime{}, err
	}
	pool, password, err := postgres.NewSwitchablePool(ctx, url, agentPoolConns)
	if err != nil {
		files.close()
		return agentRuntime{}, err
	}
	finisher := &setupFinisher{
		configPath: env.configPath, agent: a.Name, credFile: a.Store.CredentialFile, files: files,
		login: targetOf(pool.Config().ConnConfig), password: password, reset: pool.Reset,
		connect: connectAgent, log: log,
	}
	// Every read a tool call makes on the agent's connection is charged to
	// the call's result budget (CONTRACT.md, QUERY_TIMEOUT SIZE_LIMIT, one
	// budget per call). Reads outside a call (upkeep, the person's socket)
	// carry no budget and are not charged.
	budgeted := resultsize.Budgeted(pool)
	probe := postgres.Probe{Q: budgeted, Migrations: guard.Migrations(), Kept: KeptSetAside(env.pins, a.Name, log)}
	logGuard(ctx, probe, log)
	// The agent's classification map, and the values of IDENTIFIER columns
	// it reads added to the dictionary before they leave the engine: query
	// rows in the service, RETURNING rows inside the write's transaction.
	classes := piidict.NewMap(log.With("component", "pii"))
	observer := piidict.NewObserver(classes, env.dict)
	store := postgres.NewStore(budgeted, limits, time.Now).WithReturned(observer.Returned)
	secrets := linkSecrets(env.stateDir, a.Name, log)
	var relay agent.LinkRelay
	if env.relay != nil {
		relay = env.relay
	}
	if env.relayLinks != nil {
		env.relayLinks.add(a.Name, secrets, env.dropLink)
	}
	if env.records != nil {
		env.records.add(a.Name, pool)
	}
	blind := agent.NewBlindCache(func(ctx context.Context, tables []string) ([]string, error) {
		return guard.RLSBlindTables(ctx, budgeted, "", tables)
	})
	svc := agent.NewService(agent.Deps{
		Name:          a.Name,
		Store:         store,
		PagesBase:     env.pagesBase,
		LinkBudget:    env.cfg.LinkBudgetOrDefault(),
		Commands:      cmds,
		PagesOrigin:   env.pagesOrigin,
		Links:         secrets,
		Relay:         relay,
		RLS:           blind,
		Log:           log,
		Now:           time.Now,
		OperatedBy:    env.cfg.OperatedBy,
		DevLocalPages: env.cfg.DevLocalPages,
		SameUser:      !env.cfg.Service(),
		Setup:         a.Setup,
		Probe:         probe,
		Vault:         env.vault,
		Portal:        env.portal,
		Plugins:       env.plugins,
		Update:        env.updateNotice(),
		EngineRecord: func(ctx context.Context, id string) (*guard.RecordedEngine, error) {
			r, err := guard.EngineRecord(ctx, pool, id)
			return r, postgres.MapError(err)
		},
		DirectServed: env.direct != nil,
		Receipts:     env.receipts,
		Finisher:     finisher,
		PII:          observer.On(pool),
		Catalog:      postgres.NewCatalog(budgeted, limits, pool.Config().ConnConfig.Database).WithHost(pool.Config().ConnConfig.Host),
		Columns:      postgres.NewColumnOrder(budgeted),
		Classes:      storeClasses{BoundMap: classes.On(pool)},
	})
	return agentRuntime{
		svc: svc,
		upkeep: upkeep.New(a.Name, buildinfo.Version, postgres.NewUpkeep(pool), log, time.Now).WithPins(env.pins).WithRLSCache(blind).
			WithOperatedBy(env.cfg.OperatedBy).WithGate(svc.AdmitTick).
			WithPII(piidict.NewWatch(a.Name, classes, pool, log.With("component", "pii"))),
		ledger: piiLedger{Ledger: gatedLedger{inner: person.NewDBLedger(pool, time.Now), admit: svc.Admit}, dict: env.dict},
		info:   agentInfo(svc, pool.Config().ConnConfig.Config),
		scan:   piidict.ScanSource{Agent: a.Name, DB: pool, Classes: classes, Limits: limits},
		close: func() {
			pool.Close()
			files.close()
		},
	}, nil
}

// agentFilesFor is how the engine reaches agent a's files: by path, or,
// started as root without --user, through directories opened without
// following a link, from the computed credential path only (rootFiles).
func agentFilesFor(env agentEnv, a config.Agent) (agentFiles, error) {
	if !env.asRoot {
		return pathFiles{configPath: env.configPath, credFile: a.Store.CredentialFile}, nil
	}
	return openRootFiles(env.configPath, a.Name, a.Store.CredentialFile)
}

// agentInfo answers the person socket's STATUS with the agent's status tool
// and TARGET with the database its credential connects to.
func agentInfo(svc *agent.Service, conn pgconn.Config) person.AgentInfo {
	t := setupcode.ConnTarget(conn.Host, int(conn.Port), conn.Database, conn.User)
	return person.AgentInfo{
		Status: func(ctx context.Context) (json.RawMessage, error) {
			r, err := svc.Status(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(r)
		},
		Target: person.TargetDTO(t),
	}
}

// logGuard logs the agent's guard as the engine starts serving it. A guard
// that is missing or misses a breaking migration, or a database the engine
// cannot reach, does not stop the engine: the agent gets status and its
// problems, and the guard is read again on each call.
func logGuard(ctx context.Context, probe agent.Probe, log *slog.Logger) {
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

// KeptSetAside reads the pins agent set aside after reinstalls from its
// pin (chainpin.Pin.SetAside), for the reinstall notice. A pin that cannot
// be read is logged and adds nothing: the ledger still shows the notice.
func KeptSetAside(pins upkeep.Pins, agent string, log *slog.Logger) func() []action.SetAside {
	return func() []action.SetAside {
		p, _, err := pins.Load(agent)
		if err != nil {
			log.Warn("read the kept copy of set-aside pins", "agent", agent, "err", err)
		}
		return p.SetAside
	}
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

// dropLink ends what a dropped link has: its token at the Vault and its
// direct sessions.
func (env agentEnv) dropLink(token channel.LinkToken) {
	if env.relay != nil {
		env.relay.Unregister(token)
	}
	if env.direct != nil {
		env.direct.EndLink(token)
	}
}

// updateNotice is the cached newer release, or nil when the check is off.
func (env agentEnv) updateNotice() func() *updatecheck.Notice {
	if env.update == nil {
		return nil
	}
	return env.update.Cached
}
