package setuprun

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Backend is what a setup reads and writes in the database: the guard's SQL
// functions and the sample schema. An outbound adapter implements it; the
// program that runs a setup (internal/app, or pkg/setup for a program that
// calls it directly) builds one and hands it over with Use.
type Backend interface {
	LatestVersion() int
	Migrations() []guardmodel.Migration
	StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status

	InstalledPrefix(ctx context.Context, q Querier) (string, error)
	InstalledVersion(ctx context.Context, q Querier) (int, error)
	CheckUsable(ctx context.Context, q Querier) error
	// UnusableInstall reports whether err is CheckUsable's refusal of an
	// older install.
	UnusableInstall(err error) bool
	RemoveOldInstallDoc() string

	SetupsFor(ctx context.Context, q Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error)
	RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (Statement, error)
	// SetupRefusal is the refusal code record_setup raised in err.
	SetupRefusal(err error) (string, bool)

	AgentRoleExists(ctx context.Context, q Querier, n guardmodel.Names, agent string) (bool, error)
	AgentRoles(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	RoleStatementTimeout(ctx context.Context, q Querier, role string) (RoleTimeouts, error)
	GrantedTables(ctx context.Context, q Querier, role string) ([]string, error)
	AllTablesIn(ctx context.Context, q Querier, schema string) (SchemaTables, error)
	AgentBlindTables(ctx context.Context, q Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]BlindTable, error)
	RLSBlindTables(ctx context.Context, q Querier, role string, tables []string) ([]string, error)
	// MissingTables is the tables of a plan's refusal for tables that do not exist.
	MissingTables(err error) ([]string, bool)

	PlanInit(ctx context.Context, q Querier, opts InitOptions) (Script, error)
	PlanUninstall(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	UncoveredTables(ctx context.Context, q Querier) ([]Uncovered, error)

	Engines(ctx context.Context, q Querier, admin bool) ([]RecordedEngine, error)
	RecordEngineStatement(publicKey []byte, guardVersion int) Statement

	DemoSchema() string
	DemoPlanDrop(ctx context.Context, q Querier) ([]string, error)
	DemoApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (kept bool, err error)
}

var backend Backend

// Use sets the backend every setup in this process runs on. A program calls
// it once at start, before any setup; a later call replaces it.
func Use(b Backend) { backend = b }

func be() Backend {
	if backend == nil {
		panic("setuprun: no backend; call setuprun.Use first")
	}
	return backend
}
