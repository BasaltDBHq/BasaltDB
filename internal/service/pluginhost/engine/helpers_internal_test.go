//go:build unix

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/laststop"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pluginledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/resultsize"
	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/updatecheck"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
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

// service builds the agent service over the store; set fills in the rest of
// its dependencies (logger, links, relay and so on).
func (p pgAgent) service(set func(*agent.Deps)) *agent.Service {
	d := agent.Deps{
		Name: "bot", Store: p.store,
		Log: quietLog(), Now: time.Now,
	}
	if set != nil {
		set(&d)
	}
	return agent.NewService(d)
}

func problemCodes(r agent.StatusReport) []string {
	out := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

// runtimeOf is the agent as the engine's runtime serves it, for the plugin
// feature: the agent service over its own connection, which reports ep's
// plugins in its status, and the ledger the plugin event writer reaches it by.
func runtimeOf(t *testing.T, a *guardtest.Agent, ep *Plugins) (*agent.Service, map[string]AgentLedger) {
	t.Helper()
	pool, err := postgres.NewPool(context.Background(), a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	pg := newPGAgent(t, a.URL, 2)
	svc := pg.service(func(dp *agent.Deps) {
		dp.Plugins = ep
		dp.Probe = testProbe{postgres.Probe{Q: pool, Migrations: guard.Migrations()}}
	})
	return svc, map[string]AgentLedger{"bot": {ports: testPorts, db: pool, admit: pluginAdmit(svc)}}
}

// pluginAdmit is svc's admission for plugin records, as the app builds it.
func pluginAdmit(svc *agent.Service) func(context.Context) error {
	return func(ctx context.Context) error {
		err := svc.Admit(ctx)
		var te *toolresult.ToolError
		var se *agent.SetupError
		if errors.As(err, &te) || errors.As(err, &se) {
			return fmt.Errorf("%w: %w", ErrNotAdmitted, err)
		}
		return err
	}
}

// testPorts are the real adapters, as the app builds them.
var testPorts = Ports{
	Guard:            pluginledger.Ledger{},
	Network:          osservice.PluginNetwork,
	InGroup:          osservice.InGroup,
	SystemdOverrides: osservice.SystemdOverridesOnMachine,
	NewUnitHost: func(cfg config.Config, goos, configPath, engineUser string) UnitHost {
		return osservice.NewPluginUnitHost(cfg, goos, configPath, engineUser)
	},
}

// testProbe is the store's probe as the agent reads it; these tests have no
// reinstall to tell of.
type testProbe struct{ postgres.Probe }

func (testProbe) ReinstallNotice(context.Context, int) (string, bool, error) { return "", false, nil }

// testHost is what the app gives the agent service (app.agentHost), for the
// tests that build one.
func testHost() agent.Host {
	return agent.Host{
		StartCommand: osservice.StartCommand,
		RestartArgs:  osservice.RestartArgs,
		StartHoldOffUntil: func(stop agent.LastStop, configPath string, now time.Time) (time.Time, bool) {
			return laststop.StartHoldOffUntil(laststop.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
		},
		CrashReports: func(dirs ...string) []agent.CrashReport {
			reports := crash.List(dirs...)
			out := make([]agent.CrashReport, 0, len(reports))
			for _, r := range reports {
				out = append(out, agent.CrashReport{
					ID: r.ID, Time: r.Time, Version: r.Version, Command: r.Command,
					IssueURL: func(limit int) string { link, _, _ := r.IssueURLWithin(limit); return link },
				})
			}
			return out
		},
		VaultConflict:        vault.IsConflict,
		ErrVaultNotConnected: vault.ErrNotConnected,
		AfterAnswer:          vault.AfterAnswer,
		RotateSession:        vault.RotateSession,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
		ErrRevertNotFound:      ledger.ErrRevertNotFound,
		ErrApprovalNotFound:    ledger.ErrApprovalNotFound,
		ErrInvalidParams:       ledger.ErrInvalidParams,
		ErrInvalidIntent:       guard.ErrInvalidIntent,
		ApprovalSortSpec:       ledger.ApprovalSortSpec,
		Record:                 func(ch action.Change, rows []action.RowChange) any { return ledger.RecordFromDomain(ch, rows) },
		PluginApprovalsVersion: guard.PluginApprovalsVersion,
		LatestGuardVersion:     guard.LatestVersion,
		UpdateMessage: func(n agent.UpdateNotice, exe string) string {
			return updatecheck.Notice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}.AgentMessage(exe)
		},
	}
}
