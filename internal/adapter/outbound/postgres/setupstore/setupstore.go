// Package setupstore is the database side of a setup: the guard's SQL
// functions and the sample schema, as the setup service's backend port
// asks for them.
package setupstore

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Store has no state: it runs on the connection each call is given.
type Store struct{}

// New is the Store a program hands to the setup service.
func New() Store { return Store{} }

func (Store) LatestVersion() int                 { return guard.LatestVersion() }
func (Store) Migrations() []guardmodel.Migration { return guard.Migrations() }
func (Store) StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status {
	return guard.StatusAt(installed, migs)
}

func (Store) InstalledPrefix(ctx context.Context, q guard.Querier) (string, error) {
	return guard.InstalledPrefix(ctx, q)
}

func (Store) InstalledVersion(ctx context.Context, q guard.Querier) (int, error) {
	return guard.InstalledVersion(ctx, q)
}

func (Store) CheckUsable(ctx context.Context, q guard.Querier) error {
	return guard.CheckUsable(ctx, q)
}
func (Store) UnusableInstall(err error) bool { return errors.Is(err, guard.ErrUnusableInstall) }
func (Store) RemoveOldInstallDoc() string    { return guard.RemoveOldInstallDoc }

func (Store) SetupsFor(ctx context.Context, q guard.Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error) {
	return guard.SetupsFor(ctx, q, id, role)
}

func (Store) RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (guardmodel.Statement, error) {
	return guard.RecordSetupStatement(n, s)
}

func (Store) SetupRefusal(err error) (string, bool) { return guard.SetupRefusal(err) }

func (Store) AgentRoleExists(ctx context.Context, q guard.Querier, n guardmodel.Names, agent string) (bool, error) {
	return guard.AgentRoleExists(ctx, q, n, agent)
}

func (Store) AgentRoles(ctx context.Context, q guard.Querier, n guardmodel.Names) ([]string, error) {
	return guard.AgentRoles(ctx, q, n)
}

func (Store) RoleStatementTimeout(ctx context.Context, q guard.Querier, role string) (guardmodel.RoleTimeouts, error) {
	return guard.RoleStatementTimeout(ctx, q, role)
}

func (Store) GrantedTables(ctx context.Context, q guard.Querier, role string) ([]string, error) {
	return guard.GrantedTables(ctx, q, role)
}

func (Store) AllTablesIn(ctx context.Context, q guard.Querier, schema string) (guardmodel.SchemaTables, error) {
	return guard.AllTablesIn(ctx, q, schema)
}

func (Store) AgentBlindTables(ctx context.Context, q guard.Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]guardmodel.BlindTable, error) {
	return guard.AgentBlindTables(ctx, q, n, spec)
}

func (Store) RLSBlindTables(ctx context.Context, q guard.Querier, role string, tables []string) ([]string, error) {
	return guard.RLSBlindTables(ctx, q, role, tables)
}

// MissingTables is the tables of PlanInit's refusal for tables that do not exist.
func (Store) MissingTables(err error) ([]string, bool) {
	var missing *guard.MissingTablesError
	if !errors.As(err, &missing) {
		return nil, false
	}
	return missing.Tables, true
}

func (Store) PlanInit(ctx context.Context, q guard.Querier, opts guardmodel.InitOptions) (guardmodel.Script, error) {
	return guard.PlanInit(ctx, q, opts)
}

func (Store) PlanUninstall(ctx context.Context, q guard.Querier, n guardmodel.Names) ([]string, error) {
	return guard.PlanUninstall(ctx, q, n)
}

func (Store) UncoveredTables(ctx context.Context, q guard.Querier) ([]guardmodel.Uncovered, error) {
	return guard.UncoveredTables(ctx, q)
}

func (Store) Engines(ctx context.Context, q guard.Querier, admin bool) ([]guardmodel.RecordedEngine, error) {
	return guard.Engines(ctx, q, admin)
}

func (Store) RecordEngineStatement(publicKey []byte, guardVersion int) guardmodel.Statement {
	return guard.RecordEngineStatement(publicKey, guardVersion)
}

func (Store) DemoSchema() string { return demo.Schema }

func (Store) DemoPlanDrop(ctx context.Context, q guard.Querier) ([]string, error) {
	return demo.PlanDrop(ctx, q)
}

func (Store) DemoApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (bool, error) {
	return demo.ApplyDrop(ctx, tx, drops)
}

func (Store) HasPasskeyFor(ctx context.Context, q guard.Querier, origin string) (bool, error) {
	return guard.HasPasskeyFor(ctx, q, origin)
}

func (Store) CurrentDatabase(ctx context.Context, q guard.Querier) (string, error) {
	return guard.CurrentDatabase(ctx, q)
}

func (Store) MetaOwner(ctx context.Context, q guard.Querier) (string, error) {
	return guard.MetaOwner(ctx, q)
}

func (Store) Run(ctx context.Context, q guard.Querier, sql string) error {
	return guard.Run(ctx, q, sql)
}

func (Store) ApplyScript(ctx context.Context, tx pgx.Tx, s guardmodel.Script) error {
	return guard.ApplyScript(ctx, tx, s)
}
