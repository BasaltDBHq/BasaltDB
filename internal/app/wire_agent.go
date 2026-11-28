package app

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/status"

	"github.com/basaltdbhq/basaltdb/internal/engine"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/status/out/crashfile"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"
)

// AgentHostDeps are the agent service's dependencies that come from the
// adapters it may not import: the error values it tells apart, the service
// manager, the crash directory, the Vault session. Each agent's wiring
// fills the rest on top of it, and the service refuses a Deps that lacks
// one.
func AgentHostDeps() Deps {
	var d Deps
	d.Core.ServiceManager = AgentServiceManager()
	d.Core.Errors = AgentErrors()
	d.Agent.Record = func(ch action.Change, rows []action.RowChange) any { return ledger.RecordFromDomain(ch, rows) }
	d.Approval.SortSpec = ledger.ApprovalSortSpec
	d.Revert.AfterAnswer = vault.AfterAnswer
	d.Revert.RotateSession = vault.RotateSession
	d.Delivery.VaultConflict = vault.IsConflict
	d.Delivery.ErrVaultNotConnected = vault.ErrNotConnected
	d.Status.CrashReports = agentCrashReports
	d.Status.CrashFile = crashfile.Find
	d.Status.LatestGuardVersion = guard.LatestVersion
	d.Status.UpdateMessage = agentUpdateMessage
	d.Status.StartHoldOffUntil = agentStartHoldOffUntil
	d.Plugin.ApprovalsVersion = guard.PluginApprovalsVersion
	return d
}

// AgentServiceManager is the host's service manager, for the agent's
// commands.
func AgentServiceManager() guidance.ServiceManager { return osservice.Manager() }

// AgentErrors are the adapters' error values the agent maps to tool errors.
func AgentErrors() guidance.ErrorMap { return pgerrors.Map() }

// agentEngineHost is what the status of an engine that is down reads from
// the host.
func agentEngineHost() status.EngineHost {
	return status.EngineHost{
		LatestGuardVersion: guard.LatestVersion, ReadLastStop: engine.LastStopReader(engineos.OS{}), StartHoldOffUntil: agentStartHoldOffUntil,
		ConfigDirGone: configDirGone,
	}
}

func agentStartHoldOffUntil(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool) {
	return laststop.StartHoldOffUntil(servicespec.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
}

func agentCrashReports(dirs ...string) []status.CrashReport {
	reports := crash.List(dirs...)
	out := make([]status.CrashReport, 0, len(reports))
	for _, r := range reports {
		out = append(out, status.CrashReport{
			ID: r.ID, Time: r.Time, Version: r.Version, Command: r.Command,
			IssueURL: func(limit int) string { link, _, _ := r.IssueURLWithin(limit); return link },
		})
	}
	return out
}

func agentUpdateMessage(n status.ReleaseNotice, exe string) string {
	return updatecheck.Notice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}.AgentMessage(exe)
}

// agentProbe is the store's probe as the agent reads it: the reinstall
// notice is the ledger's, rendered here.
type agentProbe struct{ postgres.Probe }

func (p agentProbe) ReinstallNotice(ctx context.Context, limit int) (string, bool, error) {
	return ledger.ReadReinstallMessage(ctx, p.Probe, limit)
}

// agentAccess is pgcatalog.ListAccess as the agent reads it.
func agentAccess(ctx context.Context, db pgcatalog.Querier) (status.CatalogAccess, error) {
	a, err := pgcatalog.ListAccess(ctx, db)
	return status.CatalogAccess(a), err
}

// agentEngineRecord is the engine's row as the agent reads it.
func agentEngineRecord(r *guardmodel.RecordedEngine) *status.EngineRecord {
	if r == nil {
		return nil
	}
	return &status.EngineRecord{RecordedAt: r.RecordedAt, RevokedAt: r.RevokedAt}
}

// agentUpdate is the update checker's cached notice as the agent reads it.
func agentUpdate(cached func() *updatecheck.Notice) func() *status.ReleaseNotice {
	if cached == nil {
		return nil
	}
	return func() *status.ReleaseNotice {
		n := cached()
		if n == nil {
			return nil
		}
		return &status.ReleaseNotice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}
	}
}

// NewAgentCatalog is the store's catalog as the agent reads it.
func NewAgentCatalog(c *postgres.Catalog) agentsvc.Catalog { return agentcatalog.New(c) }

// NewAgentProbe is the store's probe as the agent reads it.
func NewAgentProbe(p postgres.Probe) status.Probe { return agentProbe{p} }

// configDirGone reports whether the folder of configPath does not exist:
// the removal deleted it (status REMOVED). Any other error is not a removal.
func configDirGone(configPath string) bool {
	_, err := os.Lstat(filepath.Dir(configPath))
	return errors.Is(err, fs.ErrNotExist)
}
