package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/connectrpc"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/handofffiles"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The removal hand-off on an agent-operated engine (CONTRACT.md, Connect,
// The removal hand-off). handoff.SelfRemove decides; this file wires it and
// runs what it decided: the engine stops serving, and once everything it
// opened is closed, it deletes its own folders (selfremove_unix.go) and
// sends the signed ReportRemoved. A service engine, and one that serves
// other agents, stays and reports why.

// selfRemoval carries a confirmed removal from the agent's collect loop to
// the end of runWith, which stops the engine for it.
type selfRemoval struct {
	mu        sync.Mutex
	confirmed *handoff.Removed
	stop      func()
}

// confirm records r and stops the engine.
func (s *selfRemoval) confirm(r handoff.Removed) {
	s.mu.Lock()
	s.confirmed = &r
	stop := s.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// setStop is how runWith stops the engine for a confirmed removal.
func (s *selfRemoval) setStop(stop func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop = stop
}

// taken is the confirmed removal, or nil.
func (s *selfRemoval) taken() *handoff.Removed {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed
}

// reportTimeout bounds the ReportRemoved the engine sends before it exits:
// a service that does not answer never keeps it running.
const reportTimeout = 20 * time.Second

// newSelfRemove is agent a's removal watch on an agent-operated engine:
// it reads engine.json at every tick, so a removal link basalt init
// --remove writes while the engine runs is collected without a restart.
// nil when the engine is person-operated, runs as root or its key is
// refused. readCredential reads the agent's credential file at the time of
// the fresh login that shows its role is gone.
func newSelfRemove(env agentEnv, a config.Agent, cc *pgx.ConnConfig, readCredential func() (string, error), log *slog.Logger) func(context.Context) {
	if !env.cfg.AgentOperated() || env.asRoot || env.keys == nil {
		return nil
	}
	files := handofffiles.SetupFiles{ConfigPath: env.configPath, Agent: a.Name, CredFile: a.Store.CredentialFile, Pins: trustPins{}}
	t := setupcode.ConnTarget(cc.Host, int(cc.Port), cc.Database, cc.User)
	r := handoff.NewSelfRemove(handoff.SelfRemoveOptions{
		Agent: a.Name, Credential: setupcode.Address(t),
		Collector: handoff.NewClient(connectrpc.New(env.handoff.HTTP, env.handoff.serviceURL()), env.keys, env.handoff.now()),
		Login: func(ctx context.Context) error {
			dsn, err := readCredential()
			if err != nil {
				return err
			}
			return freshLogin(ctx, dsn)
		},
		Pending: files.PendingRemoval,
		Confirmed: func(ctx context.Context, rm handoff.Removed) bool {
			return takeRemoval(ctx, env.configPath, rm, env.removal, log)
		},
		Log: log.With("component", "connect"), Now: env.handoff.now(),
	})
	return r.Run
}

// errRemovalGone is a confirmed removal engine.json no longer records:
// nothing is removed.
var errRemovalGone = errors.New("engine.json no longer records this removal")

// currentRemoval reads engine.json again for the confirmed removal rm, so
// what happens follows the config now, not the one the engine started
// with: errRemovalGone when the agent's pending removal is no longer
// rm's; KEPT SERVICE for a service engine (its removal job removes it);
// KEPT OTHER_AGENTS when any other agent is configured, so the engine stays
// for it and nothing of it is deleted.
func currentRemoval(configPath string, rm handoff.Removed) (config.Config, string, error) {
	cfg, err := config.LoadNoFollow(configPath)
	if err != nil {
		return config.Config{}, "", err
	}
	mine := false
	for _, a := range cfg.Agents {
		if a.Name == rm.Agent && a.Removal != nil && a.Removal.SetupID == rm.SetupID {
			mine = true
		}
	}
	switch {
	case !mine:
		return cfg, "", errRemovalGone
	case cfg.Service():
		return cfg, handoff.KeptService, nil
	case len(cfg.Agents) > 1:
		return cfg, handoff.KeptOtherAgents, nil
	}
	return cfg, "", nil
}

// takeRemoval decides on a confirmed removal: it reports KEPT and serves
// on when the engine stays, stops the engine for it otherwise, and keeps
// the watch going (false) when engine.json no longer records it.
func takeRemoval(ctx context.Context, configPath string, rm handoff.Removed, removal *selfRemoval, log *slog.Logger) bool {
	_, kept, err := currentRemoval(configPath, rm)
	switch {
	case err != nil:
		log.Warn("the removal is not taken", "setupId", rm.SetupID, "err", err)
		return false
	case kept != "":
		reportRemoved(ctx, rm, handoff.RemovedKept, kept, log)
		return true
	case removal == nil:
		return false
	}
	removal.confirm(rm)
	return true
}

// bothRuns is one agent run of a and b, either of which may be nil; nil
// when both are.
func bothRuns(a, b func(context.Context)) func(context.Context) {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(ctx context.Context) {
		var wg sync.WaitGroup
		wg.Go(func() { a(ctx) })
		b(ctx)
		wg.Wait()
	}
}

// freshLogin logs in once with dsn on a connection of its own (never the
// pool's: an open session outlives a DROP ROLE): handoff.ErrLoginRefused
// when the database refuses the login.
func freshLogin(ctx context.Context, dsn string) error {
	ctx, cancel := context.WithTimeout(ctx, setup.LoginTimeout)
	defer cancel()
	conn, err := pgdial.Connect(ctx, dsn)
	switch {
	case err == nil:
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil
	case setup.LoginRefused(pgErrors{}, err):
		return handoff.ErrLoginRefused
	}
	return err
}

// reportRemoved sends rm's ReportRemoved, best effort: a service that does
// not answer, or an older one without the call, is logged.
func reportRemoved(ctx context.Context, rm handoff.Removed, result, reason string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
	defer cancel()
	if err := rm.Report(ctx, result, reason); err != nil {
		log.Warn("tell the connect page that the engine removed itself", "setupId", rm.SetupID, "err", err)
	}
}

// finishSelfRemoval deletes the engine's folders after runWith returned for
// the removal rm and reports the result. Nothing of the engine runs any
// more, so nothing writes a file again. engine.json is read once more:
// the folders and files come from it as it is now, and an agent added or a
// removal replaced since the confirmation deletes nothing.
func finishSelfRemoval(ctx context.Context, configPath string, rm *handoff.Removed, log *slog.Logger) {
	cfg, kept, err := currentRemoval(configPath, *rm)
	switch {
	case err != nil:
		log.Warn("BasaltDB did not remove itself from this machine", "err", err)
		reportRemoved(ctx, *rm, handoff.RemovedKept, handoff.KeptDeleteFailed, log)
		return
	case kept != "":
		reportRemoved(ctx, *rm, handoff.RemovedKept, kept, log)
		return
	}
	result, reason := handoff.RemovedAll, ""
	if err := removeEngineFiles(cfg, configPath, rm.Agent); err != nil {
		result, reason = handoff.RemovedKept, keptReason(err)
		log.Warn("BasaltDB could not remove all of itself from this machine", "err", err)
	} else {
		log.Info("BasaltDB removed itself from this machine; only the basalt binary stays")
	}
	reportRemoved(ctx, *rm, result, reason, log)
}

// errCredentialKept is a credential file outside the engine's folders that
// is not a plain file of the engine's user: it stays.
var errCredentialKept = errors.New("the agent's credential file is not one basalt wrote, or not a plain file of this user, so it stays")

func keptReason(err error) string {
	if errors.Is(err, errCredentialKept) {
		return handoff.KeptCredentialFile
	}
	return handoff.KeptDeleteFailed
}
