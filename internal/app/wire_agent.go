package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"
)

// AgentHostDeps are the agent service's dependencies that come from the
// adapters it may not import: the error values it tells apart, the service
// manager, the crash directory, the Vault session. Each agent's wiring
// fills the rest on top of it, and the service refuses a Deps that lacks
// one.
func AgentHostDeps() agent.Deps {
	var d agent.Deps
	d.Core.ServiceManager = AgentServiceManager()
	d.Core.Errors = AgentErrors()
	d.Write.Record = func(ch action.Change, rows []action.RowChange) any { return ledger.RecordFromDomain(ch, rows) }
	d.Approval.ErrNotFound = ledger.ErrApprovalNotFound
	d.Approval.SortSpec = ledger.ApprovalSortSpec
	d.Revert.ErrNotFound = ledger.ErrRevertNotFound
	d.Revert.AfterAnswer = vault.AfterAnswer
	d.Revert.RotateSession = vault.RotateSession
	d.Delivery.VaultConflict = vault.IsConflict
	d.Delivery.ErrVaultNotConnected = vault.ErrNotConnected
	d.Status.CrashReports = agentCrashReports
	d.Status.LatestGuardVersion = guard.LatestVersion
	d.Status.UpdateMessage = agentUpdateMessage
	d.Status.StartHoldOffUntil = agentStartHoldOffUntil
	d.Plugin.ApprovalsVersion = guard.PluginApprovalsVersion
	return d
}

// AgentServiceManager is the host's service manager, for the agent's
// commands.
func AgentServiceManager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}

// AgentErrors are the adapters' error values the agent maps to tool errors.
func AgentErrors() guidance.ErrorMap {
	return guidance.ErrorMap{
		InvalidParams: ledger.ErrInvalidParams,
		InvalidIntent: guard.ErrInvalidIntent,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
	}
}

// AgentEngineHost is what the status of an engine that is down reads from
// the host.
func AgentEngineHost() agent.EngineHost {
	return agent.EngineHost{LatestGuardVersion: guard.LatestVersion, ReadLastStop: engine.ReadLastStop, StartHoldOffUntil: agentStartHoldOffUntil}
}

func agentStartHoldOffUntil(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool) {
	return laststop.StartHoldOffUntil(servicespec.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
}

func agentCrashReports(dirs ...string) []agent.CrashReport {
	reports := crash.List(dirs...)
	out := make([]agent.CrashReport, 0, len(reports))
	for _, r := range reports {
		out = append(out, agent.CrashReport{
			ID: r.ID, Time: r.Time, Version: r.Version, Command: r.Command,
			IssueURL: func(limit int) string { link, _, _ := r.IssueURLWithin(limit); return link },
		})
	}
	return out
}

func agentUpdateMessage(n agent.ReleaseNotice, exe string) string {
	return updatecheck.Notice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}.AgentMessage(exe)
}

// AgentTools are the tools of svc as the MCP server serves them.
func AgentTools(svc *agent.Service) []mcpserver.Tool {
	return mcpserver.ToolsFrom(agent.Tools(svc), agent.WithMeta)
}

// EngineDownServer is what basalt mcp answers with itself while the engine
// is down: the engine-down tools, and the answer to a request the engine
// took but closed the connection without answering.
type EngineDownServer struct {
	*mcpserver.Server
	down agent.EngineDown
}

// NewEngineDownServer is the engine-down tools of down, served as an
// agent's MCP server.
func NewEngineDownServer(down agent.EngineDown) EngineDownServer {
	info := mcpserver.Info{Name: "basalt", Version: buildinfo.Version, Instructions: Instructions}
	return EngineDownServer{Server: mcpserver.NewServer(info, mcpserver.ToolsFrom(down.Tools(), nil)...), down: down}
}

// Abandoned answers a request the engine took and never answered (it
// closed the connection: it stopped, or it refused the peer), always with
// an error and never by running the call again: a tools/call gets UNAVAILABLE
// ENGINE_UNREACHABLE with its steps, any other request a JSON-RPC error. A
// notification gets nothing.
func (s EngineDownServer) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	req, ok := mcpserver.RequestOf(line)
	if !ok {
		return nil
	}
	if req.Method != "tools/call" {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, agent.AbandonedMessage)
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &p) // a call without a name is still answered
	te := s.down.Abandoned(p.Name)
	if te == nil {
		return mcpserver.WriteError(out, req.ID, mcpserver.ErrCodeServer, agent.AbandonedMessage)
	}
	return mcpserver.WriteToolError(out, req.ID, te)
}

// agentProbe is the store's probe as the agent reads it: the reinstall
// notice is the ledger's, rendered here.
type agentProbe struct{ postgres.Probe }

func (p agentProbe) ReinstallNotice(ctx context.Context, limit int) (string, bool, error) {
	rs, err := p.Reinstalls(ctx)
	if err != nil {
		return "", false, err
	}
	msg, ok := ledger.ReinstallPersonMessage(rs, limit)
	return msg, ok, nil
}

// agentCatalog is the store's catalog as the agent reads it, in the
// agent's own types.
type agentCatalog struct{ *postgres.Catalog }

func relationOf(r pgcatalog.Relation) agent.CatalogRelation { return agent.CatalogRelation(r) }

func (c agentCatalog) Relations(ctx context.Context) ([]agent.CatalogRelation, int, error) {
	rs, n, err := c.Catalog.Relations(ctx)
	out := make([]agent.CatalogRelation, len(rs))
	for i, r := range rs {
		out[i] = relationOf(r)
	}
	return out, n, err
}

func (c agentCatalog) Find(ctx context.Context, schema, name string) (agent.CatalogRelation, bool, error) {
	r, ok, err := c.Catalog.Find(ctx, schema, name)
	return relationOf(r), ok, err
}

func (c agentCatalog) Describe(ctx context.Context, oid uint32) (agent.CatalogDetail, error) {
	d, err := c.Catalog.Describe(ctx, oid)
	out := agent.CatalogDetail{
		CatalogRelation: relationOf(d.Relation), PrimaryKey: d.PrimaryKey, Stats: agent.CatalogStats(d.Stats),
		RLS: d.RLS, CascadesIntoHidden: d.CascadesIntoHidden,
	}
	for _, col := range d.Columns {
		out.Columns = append(out.Columns, agent.CatalogColumn(col))
	}
	for _, ix := range d.Indexes {
		out.Indexes = append(out.Indexes, agent.CatalogIndex(ix))
	}
	for _, k := range d.Keys {
		out.Keys = append(out.Keys, agent.CatalogKey(k))
	}
	return out, err
}

func (c agentCatalog) Search(ctx context.Context, q string, exclude []agent.CatalogColumnKey, after *agent.CatalogSearchCursor, limit int) ([]agent.CatalogMatch, error) {
	ex := make([]pgcatalog.ColumnKey, len(exclude))
	for i, k := range exclude {
		ex[i] = pgcatalog.ColumnKey(k)
	}
	var cur *pgcatalog.SearchCursor
	if after != nil {
		v := pgcatalog.SearchCursor(*after)
		cur = &v
	}
	ms, err := c.Catalog.Search(ctx, q, ex, cur, limit)
	out := make([]agent.CatalogMatch, len(ms))
	for i, m := range ms {
		out[i] = agent.CatalogMatch{CatalogRelation: relationOf(m.Relation), Rank: m.Rank, Matched: m.Matched}
	}
	return out, err
}

// agentAccess is pgcatalog.ListAccess as the agent reads it.
func agentAccess(ctx context.Context, db pgcatalog.Querier) (agent.CatalogAccess, error) {
	a, err := pgcatalog.ListAccess(ctx, db)
	return agent.CatalogAccess(a), err
}

// agentEngineRecord is the engine's row as the agent reads it.
func agentEngineRecord(r *guardmodel.RecordedEngine) *agent.EngineRecord {
	if r == nil {
		return nil
	}
	return &agent.EngineRecord{RecordedAt: r.RecordedAt, RevokedAt: r.RevokedAt}
}

// agentUpdate is the update checker's cached notice as the agent reads it.
func agentUpdate(cached func() *updatecheck.Notice) func() *agent.ReleaseNotice {
	if cached == nil {
		return nil
	}
	return func() *agent.ReleaseNotice {
		n := cached()
		if n == nil {
			return nil
		}
		return &agent.ReleaseNotice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}
	}
}

// NewAgentCatalog is the store's catalog as the agent reads it.
func NewAgentCatalog(c *postgres.Catalog) agent.Catalog { return agentCatalog{c} }

// NewAgentProbe is the store's probe as the agent reads it.
func NewAgentProbe(p postgres.Probe) agent.Probe { return agentProbe{p} }
