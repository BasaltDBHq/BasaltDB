package setuprun

import (
	"time"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// The types this package's functions take and return, under names an
// adapter can use without importing the database packages.
type (
	// Querier is the admin connection or transaction a plan or an apply runs on.
	Querier = guard.Querier
	// Script is the ordered SQL an install, a repair or a removal runs.
	Script = guard.Script
	// Statement is one step of a Script.
	Statement = guard.Statement
	// InitOptions configures planning an install.
	InitOptions = guard.InitOptions
	// BlindTable is a table whose row-level security hides every row from the agent.
	BlindTable = guard.BlindTable
	// RegisteredPasskey is an active passkey as the setup page lists it.
	RegisteredPasskey = guard.RegisteredPasskey
	// DemoPlan is what seeding the sample schema runs.
	DemoPlan = demo.Plan
)

// ActivePasskey is an active passkey as the doctor lists it.
type ActivePasskey struct {
	Credential passkey.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}
