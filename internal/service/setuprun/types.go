package setuprun

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Querier is the admin connection or transaction a plan or an apply runs on.
// It is an alias of the interface itself, so an adapter that cannot import
// this package still implements Backend.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// The data a setup plans and reads, as guardmodel defines it.
type (
	// Script is the ordered SQL an install, a repair or a removal runs.
	Script = guardmodel.Script
	// Statement is one step of a Script.
	Statement = guardmodel.Statement
	// InitOptions configures planning an install.
	InitOptions = guardmodel.InitOptions
	// BlindTable is a table whose row-level security hides every row from the agent.
	BlindTable = guardmodel.BlindTable
	// RegisteredPasskey is an active passkey as the setup page lists it.
	RegisteredPasskey = guardmodel.RegisteredPasskey
	// DemoPlan is what seeding the sample schema runs.
	DemoPlan = guardmodel.DemoPlan
	// SchemaTables are the tables of a schema as an agent.allTables setup sees them.
	SchemaTables = guardmodel.SchemaTables
	// RecordedEngine is a row of basalt_meta.engines.
	RecordedEngine = guardmodel.RecordedEngine
	// RoleTimeouts is the statement_timeout a role has set.
	RoleTimeouts = guardmodel.RoleTimeouts
	// Uncovered is an agent-writable table or cascade target without the guard.
	Uncovered = guardmodel.Uncovered
)

// ActivePasskey is an active passkey as the doctor lists it.
type ActivePasskey struct {
	Credential passkey.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ErrForeignCredential is a credential file's string that makes the driver
// read a file of its own: it is never connected with.
var ErrForeignCredential = errors.New("the credential names a file the driver would read")
