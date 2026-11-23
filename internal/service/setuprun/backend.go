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
// calls it directly) builds one and passes it to New and the functions here.
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
	RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (guardmodel.Statement, error)
	// SetupRefusal is the refusal code record_setup raised in err.
	SetupRefusal(err error) (string, bool)

	AgentRoleExists(ctx context.Context, q Querier, n guardmodel.Names, agent string) (bool, error)
	AgentRoles(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	RoleStatementTimeout(ctx context.Context, q Querier, role string) (guardmodel.RoleTimeouts, error)
	GrantedTables(ctx context.Context, q Querier, role string) ([]string, error)
	AllTablesIn(ctx context.Context, q Querier, schema string) (guardmodel.SchemaTables, error)
	AgentBlindTables(ctx context.Context, q Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]guardmodel.BlindTable, error)
	RLSBlindTables(ctx context.Context, q Querier, role string, tables []string) ([]string, error)
	// MissingTables is the tables of a plan's refusal for tables that do not exist.
	MissingTables(err error) ([]string, bool)

	PlanInit(ctx context.Context, q Querier, opts guardmodel.InitOptions) (guardmodel.Script, error)
	PlanUninstall(ctx context.Context, q Querier, n guardmodel.Names) ([]string, error)
	UncoveredTables(ctx context.Context, q Querier) ([]guardmodel.Uncovered, error)

	Engines(ctx context.Context, q Querier, admin bool) ([]guardmodel.RecordedEngine, error)
	RecordEngineStatement(publicKey []byte, guardVersion int) guardmodel.Statement

	// HasPasskeyFor reports whether an active passkey of this database
	// belongs to origin.
	HasPasskeyFor(ctx context.Context, q Querier, origin string) (bool, error)
	// CurrentDatabase is current_database() on q.
	CurrentDatabase(ctx context.Context, q Querier) (string, error)
	// MetaOwner is the role that owns basalt_meta, "" when it does not exist.
	MetaOwner(ctx context.Context, q Querier) (string, error)
	// Run executes one statement on q.
	Run(ctx context.Context, q Querier, sql string) error
	// ApplyScript runs the script's statements on tx, in order.
	ApplyScript(ctx context.Context, tx pgx.Tx, s guardmodel.Script) error

	DemoSchema() string
	DemoPlanDrop(ctx context.Context, q Querier) ([]string, error)
	DemoApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (kept bool, err error)
}
