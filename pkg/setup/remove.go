package setup

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// Removing BasaltDB from a database (CONTRACT.md, Setup jobs, Remove Basalt)
// needs no setup code and no bot: only a connection the caller opened as
// the database's admin. CheckRemove shows what it drops; RunRemove drops
// it in one transaction once the person typed the database's name.
//
// Both use the installed guard's role prefix, or "basalt" when no guard
// is installed (a removal that stopped half way leaves only roles).

// Removal is what removing BasaltDB from the connected database drops.
type Removal struct {
	// Database is the connected database's name (current_database()): the
	// name the person types to confirm.
	Database string
	// Bots are the names of the bots that lose their access: the agent
	// roles of the guard's prefix, without the prefix, sorted.
	Bots []string
	// Lines is the summary to show, in fixed words and catalog names.
	Lines []string
	// SQL is every statement RunRemove runs now, in order.
	SQL string
	// NothingToRemove: the database has no guard, no bot role and no
	// sample schema. RunRemove still runs, and drops nothing.
	NothingToRemove bool
	// SampleSchema: the sample schema basalt_demo, which the sample-database
	// setup made, is dropped too. The person's own tables always stay.
	SampleSchema bool
}

// Removed is a finished removal.
type Removed struct {
	// Database and Bots are as in Removal, read in the removal's
	// transaction.
	Database string
	Bots     []string
	// Lines says what was removed.
	Lines []string
	// Warnings: the sample schema stayed because another object depends
	// on it.
	Warnings []string
}

// CheckRemove reads, in a transaction it rolls back, what removing
// BasaltDB from conn's database drops, and changes nothing. Errors are
// *Error: PREFIX_MISMATCH for a basalt_meta not owned by a guard role
// (<prefix>_guard), else SETUP_FAILED.
func CheckRemove(ctx context.Context, conn *pgx.Conn) (Removal, error) {
	return removal(contract.CheckRemove(ctx, setupstore.Port(conn)))
}

// removal is the service's removal plan, or its refusal.
func removal(r setuprun.ContractRemoval, err error) (Removal, error) {
	return Removal(r), asError(err)
}

// RunRemove removes BasaltDB from conn's database in one transaction. The
// admin login is the confirmation: there is no typed name. It plans again
// from the catalog, so it drops what is there now, which may differ from
// what CheckRemove showed. A failed drop is SETUP_FAILED and changes
// nothing.
func RunRemove(ctx context.Context, conn *pgx.Conn) (Removed, error) {
	return removed(contract.RunRemove(ctx, setupstore.Port(conn)))
}

// RunRemoveCode is RunRemove with a removal link's code (req.Code, checked
// at req.Now): the code must be live and carry a target and an engine key,
// and conn must be its target (TARGET_MISMATCH), all before anything is
// dropped. After it returns without an error the connect service keeps a
// REMOVED hold for the code's setupId, engine key and fingerprint
// (Describe), which the bot's engine collects.
func RunRemoveCode(ctx context.Context, conn *pgx.Conn, req Request) (Removed, error) {
	return removed(contract.RunRemoveCode(ctx, setupstore.Port(conn), adminAt(conn), contractRequest(req)))
}

// removed is the service's finished removal, or its refusal.
func removed(r setuprun.ContractRemoved, err error) (Removed, error) {
	return Removed(r), asError(err)
}
