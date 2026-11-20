package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

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
	if a.Setup.Refused {
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
	if env.asRoot {
		return agentRuntime{}, fmt.Errorf("agent %s waits for its database's address (a connect-only setup code), which an engine started as root does not collect: start the engine with --user, or as the agent's OS user", a.Name)
	}
	cmds, err := agent.NewCommands(a.Name, env.configPath, runtime.GOOS, a.InitArgs)
	if err != nil {
		return agentRuntime{}, err
	}
	if !env.cfg.Service() {
		cmds = cmds.Foreground()
	}
	var collector handoff.Collector = noKeyCollector{}
	if env.keys != nil {
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
