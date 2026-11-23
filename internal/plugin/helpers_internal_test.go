//go:build unix

package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/status"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pluginledger"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// demoTables are the tables the demo database's agents may reach.
var demoTables = []string{"public.leads"}

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// syncBuffer is a log sink the tests read back.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// pgAgent is an agent's Postgres store opened the way the engine opens it,
// for tests that use the store directly before they build the service.
type pgAgent struct {
	store  *postgres.Store
	reader *postgres.Reader
}

// newPGAgent opens a pool on the agent's connection string url and wraps it
// in the store and reader, with the default limits and the real clock.
func newPGAgent(t *testing.T, url string, conns int32) pgAgent {
	t.Helper()
	pool, err := postgres.NewPool(context.Background(), url, conns)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	return pgAgent{
		store:  postgres.NewStore(pool, limits, time.Now),
		reader: postgres.NewReader(pool, limits, time.Now),
	}
}

func problemCodes(r guidance.StatusReport) []string {
	out := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

// runtimeOf is the agent's status as the engine's runtime serves it, for the
// plugin feature: the status use case over the agent's own connection, which
// reports ep's plugins, and the ledger the plugin event writer reaches the
// agent by.
func runtimeOf(t *testing.T, a *guardtest.Agent, ep *Plugins) (*status.Service, map[string]AgentLedger) {
	t.Helper()
	pool, err := postgres.NewPool(context.Background(), a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	pg := newPGAgent(t, a.URL, 2)
	core := status.Core{
		Name: "bot", Log: quietLog(), Now: time.Now, Errors: testErrorMap(), PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget,
		Commands: guidance.NewCommands("bot", "", config.DefaultPath(runtime.GOOS), runtime.GOOS,
			guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}),
	}
	deps := status.Deps{
		Passkeys: pg.store, LatestGuardVersion: guard.LatestVersion,
		Probe: testProbe{postgres.Probe{Q: pool, Migrations: guard.Migrations()}},
	}
	if ep != nil {
		deps.Plugins = ep
	}
	svc := status.NewService(core, &deps)
	return svc, map[string]AgentLedger{"bot": {ports: testPorts, db: pool, admit: pluginAdmit(svc)}}
}

// pluginAdmit is svc's admission for plugin records, as the app builds it.
func pluginAdmit(svc interface{ Admit(context.Context) error }) func(context.Context) error {
	return func(ctx context.Context) error {
		err := svc.Admit(ctx)
		var te *toolresult.ToolError
		var se *guidance.SetupError
		if errors.As(err, &te) || errors.As(err, &se) {
			return fmt.Errorf("%w: %w", ErrNotAdmitted, err)
		}
		return err
	}
}

// testPorts are the real adapters, as the app builds them.
var testPorts = Ports{
	Guard:            pluginledger.Ledger{},
	InGroup:          osservice.InGroup,
	SystemdOverrides: osservice.SystemdOverridesOnMachine,
	NewUnitHost: func(host servicespec.PluginHost) UnitHost {
		return osservice.NewPluginUnitHost(host)
	},
}

// testProbe is the store's probe as the agent reads it; these tests have no
// reinstall to tell of.
type testProbe struct{ postgres.Probe }

func (testProbe) ReinstallNotice(context.Context, int) (string, bool, error) { return "", false, nil }
