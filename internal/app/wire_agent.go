package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/laststop"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/resultsize"
	postgres "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/updatecheck"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// The agent service takes the adapters it may not import through
// agent.Host. Importing this package fills it, so every binary that serves
// or answers for an agent has it before any tool runs.
func init() { agent.UseHost(agentHost()) }

func agentHost() agent.Host {
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

// AgentTools are the tools of svc as the MCP server serves them.
func AgentTools(svc *agent.Service) []mcp.Tool {
	return mcp.ToolsFrom(agent.Tools(svc), agent.WithMeta)
}

// EngineDownServer is what basalt mcp answers with itself while the engine
// is down: the engine-down tools, and the answer to a request the engine
// took but closed the connection without answering.
type EngineDownServer struct {
	*mcp.Server
	down agent.EngineDown
}

// NewEngineDownServer is the engine-down tools of down, served as an
// agent's MCP server.
func NewEngineDownServer(down agent.EngineDown) EngineDownServer {
	info := mcp.Info{Name: "basalt", Version: buildinfo.Version, Instructions: Instructions}
	return EngineDownServer{Server: mcp.NewServer(info, mcp.ToolsFrom(down.Tools(), nil)...), down: down}
}

// Abandoned answers a request the engine took and never answered (it
// closed the connection: it stopped, or it refused the peer), always with
// an error and never by running the call again: a tools/call gets UNAVAILABLE
// ENGINE_UNREACHABLE with its steps, any other request a JSON-RPC error. A
// notification gets nothing.
func (s EngineDownServer) Abandoned(_ context.Context, out io.Writer, line []byte) error {
	req, ok := mcp.RequestOf(line)
	if !ok {
		return nil
	}
	if req.Method != "tools/call" {
		_, message := s.down.Abandoned("")
		return mcp.WriteError(out, req.ID, mcp.ErrCodeServer, message)
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &p) // a call without a name is still answered
	te, message := s.down.Abandoned(p.Name)
	if te == nil {
		return mcp.WriteError(out, req.ID, mcp.ErrCodeServer, message)
	}
	return mcp.WriteToolError(out, req.ID, te)
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
func agentEngineRecord(r *guard.RecordedEngine) *agent.EngineRecord {
	if r == nil {
		return nil
	}
	return &agent.EngineRecord{RecordedAt: r.RecordedAt, RevokedAt: r.RevokedAt}
}

// agentUpdate is the update checker's cached notice as the agent reads it.
func agentUpdate(cached func() *updatecheck.Notice) func() *agent.UpdateNotice {
	if cached == nil {
		return nil
	}
	return func() *agent.UpdateNotice {
		n := cached()
		if n == nil {
			return nil
		}
		return &agent.UpdateNotice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}
	}
}

// NewAgentCatalog is the store's catalog as the agent reads it.
func NewAgentCatalog(c *postgres.Catalog) agent.Catalog { return agentCatalog{c} }

// NewAgentProbe is the store's probe as the agent reads it.
func NewAgentProbe(p postgres.Probe) agent.Probe { return agentProbe{p} }
