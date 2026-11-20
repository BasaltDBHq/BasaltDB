package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/handoff"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

// ErrReload is what Serve and Run return after they stopped to serve the
// config again: an agent's connect-only setup changed (the person confirmed
// its database, or basalt init --remote replaced the pending setup). The
// caller reads the config again and runs the engine anew, in this process.
var ErrReload = errors.New("the engine stopped to serve its config again")

// HandoffOptions reach the connect service and the collected database for
// the agents of a connect-only setup code. The zero value is the
// contract's: the connect service at handoff.ServiceURL, the system's
// resolver, dialer and certificate roots. Tests give their own, by
// construction only: nothing in the config or the environment changes
// them.
type HandoffOptions struct {
	ServiceURL string
	HTTP       *http.Client
	Prober     handoff.Prober
}

func (o HandoffOptions) serviceURL() string {
	if o.ServiceURL == "" {
		return handoff.ServiceURL
	}
	return o.ServiceURL
}

// errNoEngineKey is a collect while the engine key file is refused: the
// request cannot be signed.
var errNoEngineKey = errors.New("the engine key file is refused (vault.state KEY_ERROR): the address cannot be collected until it is fixed")

// rootCollector is the collector of an engine started as root without
// --user: root trusts nothing the agent's OS user could redirect, and the
// YES would write that user's credential, so it never collects. The agent
// is served degraded with the problem ENGINE_AS_ROOT; the engine's other
// agents are served as usual.
type rootCollector struct{}

func (rootCollector) Collect(context.Context, string, string) (handoff.Collected, error) {
	return handoff.Collected{}, handoff.ErrEngineAsRoot
}

func (rootCollector) Report(context.Context, string, string, handoff.Address, handoff.Reach) error {
	return handoff.ErrEngineAsRoot
}

type noKeyCollector struct{}

func (noKeyCollector) Collect(context.Context, string, string) (handoff.Collected, error) {
	return handoff.Collected{}, errNoEngineKey
}

func (noKeyCollector) Report(context.Context, string, string, handoff.Address, handoff.Reach) error {
	return errNoEngineKey
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
	files := handoffFiles{configPath: env.configPath, agent: a.Name, credFile: a.Store.CredentialFile}
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
	cmds, err := agent.NewCommands(a.Name, env.configPath, runtime.GOOS, a.InitArgs)
	if err != nil {
		return agentRuntime{}, err
	}
	if !env.cfg.Service() {
		cmds = cmds.Foreground()
	}
	var collector handoff.Collector = noKeyCollector{}
	switch {
	case env.asRoot:
		collector = rootCollector{}
		log.Warn("the agent waits for its database's address, which an engine started as root does not collect: start the engine with --user, or as the agent's OS user")
	case env.keys != nil:
		collector = handoff.NewClient(env.handoff.HTTP, env.handoff.serviceURL(), env.keys, time.Now)
	}
	reload := env.reload
	if reload == nil {
		reload = func() {}
	}
	pending, err := handoff.New(handoff.Options{
		Agent: a.Name, Setup: *a.Setup, Collector: collector, Prober: env.handoff.Prober,
		Files:   handoffFiles{configPath: env.configPath, agent: a.Name, credFile: a.Store.CredentialFile},
		Changed: reload, Log: log.With("component", "connect"), Now: time.Now,
	})
	if err != nil {
		return agentRuntime{}, fmt.Errorf("agent %s: %w", a.Name, err)
	}
	co := agent.ConnectOnly{
		Name: a.Name, Commands: cmds, OperatedBy: env.cfg.OperatedBy, SameUser: !env.cfg.Service(),
		PagesBase: env.pagesBase, PagesOrigin: env.pagesOrigin, ConnectBudget: env.cfg.ConnectLinkBudget(),
		Vault: env.vault, Handoff: pending, Log: log, Now: time.Now,
	}
	log.Info("the agent waits for its database's address from the connect page; only status and confirm_database answer", "setupId", a.Setup.SetupID)
	return agentRuntime{
		tools: co.Tools(),
		info: person.AgentInfo{Status: func(ctx context.Context) (json.RawMessage, error) {
			r, err := co.Status(ctx)
			if err != nil {
				return nil, err
			}
			return json.Marshal(r)
		}},
		run:   pending.Run,
		close: func() {},
	}, nil
}

// CollectWhileDown is basalt status for agent a's connect-only setup while
// the engine is down, in same-user mode, where the CLI runs as the
// engine's user (CONTRACT.md, The engine and a connect-only code,
// Collecting): one collect, check, probe and, for a PREVIEW address,
// report, signed with the engine's own key, and the state after. It never
// reads .secret and never confirms: only the engine's confirm_database
// does, so a database the probe passed waits for the engine.
func CollectWhileDown(ctx context.Context, cfg config.Config, configPath, goos string, a config.Agent, o HandoffOptions, log *slog.Logger) (handoff.State, error) {
	if a.Setup == nil || !a.Setup.ConnectOnly() || cfg.Service() {
		return handoff.State{}, errors.New("basalt status collects only for a waiting connect-only agent of a same-user engine")
	}
	keys, err := channel.LoadKeys(filepath.Join(cfg.StateDirFor(goos), channel.KeyFileName))
	if err != nil {
		return handoff.State{}, fmt.Errorf("the engine's key cannot be read, so the address cannot be collected: %w", err)
	}
	pending, err := handoff.New(handoff.Options{
		Agent: a.Name, Setup: *a.Setup, Collector: handoff.NewClient(o.HTTP, o.serviceURL(), keys, time.Now), Prober: o.Prober,
		Files:   handoffFiles{configPath: configPath, agent: a.Name, credFile: a.Store.CredentialFile},
		Changed: func() {}, Log: log, Now: time.Now,
	})
	if err != nil {
		return handoff.State{}, err
	}
	return pending.StatusCollect(ctx), nil
}
