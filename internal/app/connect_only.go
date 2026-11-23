package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/handoff/in/handoffmcp"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// HandoffOptions reach the connect service and the collected database for
// the agents of a connect-only setup code. The zero value is the
// contract's: the connect service at handoff.ServiceURL, the system's
// resolver, dialer and certificate roots, and the real clock. Tests give
// their own, by construction only: nothing in the config or the
// environment changes them.
type HandoffOptions struct {
	ServiceURL string
	HTTP       *http.Client
	Prober     handoff.Prober
	// Now is the clock a waiting connect-only setup uses; nil is time.Now.
	Now func() time.Time
}

func (o HandoffOptions) serviceURL() string {
	if o.ServiceURL == "" {
		return handoff.ServiceURL
	}
	return o.ServiceURL
}

func (o HandoffOptions) now() func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

// connectOnlyAgent says whether a's pending setup is a connect-only one the
// engine serves with ConnectOnly: waiting for its address, or refused. An
// agent whose credential file exists with awaitingAddress still set is one
// whose confirmation stopped half way (the engine stopped after it wrote
// the credential): only that YES writes it, so the engine finishes it and
// serves the agent on its credential.
func connectOnlyAgent(env agentEnv, a config.Agent, log *slog.Logger) (bool, error) {
	if a.Setup == nil || !a.Setup.ConnectOnly() {
		return false, nil
	}
	if a.Setup.Refused || env.asRoot {
		// As root the engine touches none of the agent's files here: a
		// confirmation it stopped in is finished by an engine started as
		// the agent's OS user.
		return true, nil
	}
	files := handoff.SetupFiles{ConfigPath: env.configPath, Agent: a.Name, CredFile: a.Store.CredentialFile, Pins: trustPins{}}
	if _, err := os.Lstat(a.Store.CredentialFile); err != nil {
		if errNotExist(err) {
			return true, nil
		}
		return false, err
	}
	unlock, err := files.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if err := files.RemoveSecret(); err != nil {
		return false, err
	}
	if err := files.ConfirmSetup(a.Setup.SetupID); err != nil {
		return false, err
	}
	log.Info("finished a confirmed connect-only setup the engine stopped in", "setupId", a.Setup.SetupID)
	return false, nil
}

// newConnectOnlyRuntime serves agent a while its connect-only setup waits:
// no credential, no connection, status and confirm_database only, and the
// collect loop. Its runtime closes nothing.
func newConnectOnlyRuntime(env agentEnv, a config.Agent, log *slog.Logger) (agentRuntime, error) {
	cmds, err := agent.NewCommands(a.Name, env.configPath, runtime.GOOS, AgentServiceManager())
	if err != nil {
		return agentRuntime{}, err
	}
	if !env.cfg.Service() {
		cmds = cmds.Foreground()
	}
	var collector handoff.Collector = handoff.NoKeyCollector{}
	switch {
	case env.asRoot:
		collector = handoff.RootCollector{}
		log.Warn("the agent waits for its database's address, which an engine started as root does not collect: start the engine as the agent's OS user")
	case env.keys != nil:
		collector = handoff.NewClient(env.handoff.HTTP, env.handoff.serviceURL(), env.keys, env.handoff.now())
	}
	reload := env.reload
	if reload == nil {
		reload = func() {}
	}
	// A root engine never collects, so it reads no probe cache either.
	var cache handoff.ProbeCache
	if !env.asRoot {
		cache = handoff.FileCache{Dir: env.stateDir}
	}
	pending, err := handoff.New(handoff.Options{
		Agent: a.Name, Setup: *a.Setup, Collector: collector, Prober: env.handoff.Prober,
		Files:   handoff.SetupFiles{ConfigPath: env.configPath, Agent: a.Name, CredFile: a.Store.CredentialFile, Pins: trustPins{}},
		Changed: reload, Log: log.With("component", "connect"), Now: env.handoff.now(), Cache: cache,
	})
	if err != nil {
		return agentRuntime{}, fmt.Errorf("agent %s: %w", a.Name, err)
	}
	co := handoffmcp.ConnectOnly{
		Name: a.Name, Commands: cmds, OperatedBy: env.cfg.OperatedBy, SameUser: !env.cfg.Service(), StartedBy: env.startedBy,
		PagesBase: env.pagesBase, PagesOrigin: env.pagesOrigin, ConnectBudget: env.cfg.ConnectLinkBudget(),
		Vault: env.vault, Handoff: pending, Log: log, Now: env.handoff.now(),
		Errors: AgentErrors(), LatestGuardVersion: AgentEngineHost().LatestGuardVersion,
		Guide: connectOnlyGuide,
	}
	log.Info("the agent waits for its database's address from the connect page; only status and confirm_database answer", "setupId", a.Setup.SetupID)
	return agentRuntime{
		tools: mcpserver.ToolsFrom(co.Tools(), nil),
		run:   pending.Run,
		close: func() {},
	}, nil
}

// newRepin is the collect loop of agent a's certificateChanged setup
// (CONTRACT.md, A changed certificate on persona 2), or nil when it has
// none, the engine runs as root or its key is refused: the certificate is
// collected only with the engine's key and as the engine's user.
func newRepin(env agentEnv, a config.Agent, cc *pgx.ConnConfig, log *slog.Logger) func(context.Context) {
	if a.Setup == nil || !a.Setup.CollectsCertificate() || env.asRoot || env.keys == nil {
		return nil
	}
	t := setupcode.ConnTarget(cc.Host, int(cc.Port), cc.Database, cc.User)
	r, err := handoff.NewRepin(handoff.RepinOptions{
		Setup: *a.Setup, Credential: setupcode.Address(t),
		Collector: handoff.NewClient(env.handoff.HTTP, env.handoff.serviceURL(), env.keys, env.handoff.now()),
		Prober:    env.handoff.Prober,
		Files:     handoff.RepinSetupFiles{SetupFiles: handoff.SetupFiles{ConfigPath: env.configPath, Agent: a.Name, CredFile: a.Store.CredentialFile, Pins: trustPins{}}},
		Log:       log.With("component", "connect"), Now: env.handoff.now(),
	})
	if err != nil {
		log.Warn("the pending certificateChanged setup cannot be collected for", "err", err)
		return nil
	}
	log.Info("the agent's pinned database presents another certificate; collecting the one trusted on the connect page", "setupId", a.Setup.SetupID)
	return r.Run
}
