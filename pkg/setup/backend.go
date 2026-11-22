package setup

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
)

// This package is the entry point for a program that runs a setup without
// the engine, so it is a composition root: it builds the adapters the setup
// service runs on and hands them over.
func init() { setuprun.Use(backend{}) }

// backend is setuprun.Backend on the guard and the sample schema.
type backend struct{}

func (backend) LatestVersion() int                 { return guard.LatestVersion() }
func (backend) Migrations() []guardmodel.Migration { return guard.Migrations() }
func (backend) StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status {
	return guard.StatusAt(installed, migs)
}

func (backend) InstalledPrefix(ctx context.Context, q setuprun.Querier) (string, error) {
	return guard.InstalledPrefix(ctx, q)
}

func (backend) InstalledVersion(ctx context.Context, q setuprun.Querier) (int, error) {
	return guard.InstalledVersion(ctx, q)
}

func (backend) CheckUsable(ctx context.Context, q setuprun.Querier) error {
	return guard.CheckUsable(ctx, q)
}
func (backend) UnusableInstall(err error) bool { return errors.Is(err, guard.ErrUnusableInstall) }
func (backend) RemoveOldInstallDoc() string    { return guard.RemoveOldInstallDoc }

func (backend) SetupsFor(ctx context.Context, q setuprun.Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error) {
	return guard.SetupsFor(ctx, q, id, role)
}

func (backend) RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (setuprun.Statement, error) {
	st, err := guard.RecordSetupStatement(n, s)
	return setuprun.Statement(st), err
}

func (backend) SetupRefusal(err error) (string, bool) { return guard.SetupRefusal(err) }

func (backend) AgentRoleExists(ctx context.Context, q setuprun.Querier, n guardmodel.Names, agent string) (bool, error) {
	return guard.AgentRoleExists(ctx, q, n, agent)
}

func (backend) AgentRoles(ctx context.Context, q setuprun.Querier, n guardmodel.Names) ([]string, error) {
	return guard.AgentRoles(ctx, q, n)
}

func (backend) RoleStatementTimeout(ctx context.Context, q setuprun.Querier, role string) (setuprun.RoleTimeouts, error) {
	t, err := guard.RoleStatementTimeout(ctx, q, role)
	return setuprun.RoleTimeouts(t), err
}

func (backend) GrantedTables(ctx context.Context, q setuprun.Querier, role string) ([]string, error) {
	return guard.GrantedTables(ctx, q, role)
}

func (backend) AllTablesIn(ctx context.Context, q setuprun.Querier, schema string) (setuprun.SchemaTables, error) {
	t, err := guard.AllTablesIn(ctx, q, schema)
	return setuprun.SchemaTables(t), err
}

func (backend) AgentBlindTables(ctx context.Context, q setuprun.Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]setuprun.BlindTable, error) {
	blind, err := guard.AgentBlindTables(ctx, q, n, spec)
	if blind == nil {
		return nil, err
	}
	out := make([]setuprun.BlindTable, len(blind))
	for i, b := range blind {
		out[i] = setuprun.BlindTable(b)
	}
	return out, err
}

func (backend) RLSBlindTables(ctx context.Context, q setuprun.Querier, role string, tables []string) ([]string, error) {
	return guard.RLSBlindTables(ctx, q, role, tables)
}

func (backend) MissingTables(err error) ([]string, bool) {
	var missing *guard.MissingTablesError
	if !errors.As(err, &missing) {
		return nil, false
	}
	return missing.Tables, true
}

func (backend) PlanInit(ctx context.Context, q setuprun.Querier, opts setuprun.InitOptions) (setuprun.Script, error) {
	in := guard.InitOptions{Names: opts.Names, Agent: opts.Agent, UpTo: opts.UpTo}
	if opts.AgentPolicies != nil {
		in.AgentPolicies = make([]guard.BlindTable, len(opts.AgentPolicies))
		for i, b := range opts.AgentPolicies {
			in.AgentPolicies[i] = guard.BlindTable(b)
		}
	}
	script, err := guard.PlanInit(ctx, q, in)
	out := setuprun.Script{Statements: make([]setuprun.Statement, len(script.Statements)), Warnings: script.Warnings}
	for i, st := range script.Statements {
		out.Statements[i] = setuprun.Statement(st)
	}
	return out, err
}

func (backend) PlanUninstall(ctx context.Context, q setuprun.Querier, n guardmodel.Names) ([]string, error) {
	return guard.PlanUninstall(ctx, q, n)
}

func (backend) UncoveredTables(ctx context.Context, q setuprun.Querier) ([]setuprun.Uncovered, error) {
	list, err := guard.UncoveredTables(ctx, q)
	out := make([]setuprun.Uncovered, len(list))
	for i, u := range list {
		out[i] = setuprun.Uncovered(u)
	}
	return out, err
}

func (backend) Engines(ctx context.Context, q setuprun.Querier, admin bool) ([]setuprun.RecordedEngine, error) {
	list, err := guard.Engines(ctx, q, admin)
	out := make([]setuprun.RecordedEngine, len(list))
	for i, e := range list {
		out[i] = setuprun.RecordedEngine(e)
	}
	return out, err
}

func (backend) RecordEngineStatement(publicKey []byte, guardVersion int) setuprun.Statement {
	return setuprun.Statement(guard.RecordEngineStatement(publicKey, guardVersion))
}

func (backend) DemoSchema() string { return demo.Schema }

func (backend) DemoPlanDrop(ctx context.Context, q setuprun.Querier) ([]string, error) {
	return demo.PlanDrop(ctx, q)
}

func (backend) DemoApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (bool, error) {
	return demo.ApplyDrop(ctx, tx, drops)
}

var _ setuprun.Backend = backend{}
