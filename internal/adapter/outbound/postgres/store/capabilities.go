package postgres

import "github.com/basaltdbhq/basaltdb/internal/core/action"

// capabilities are Postgres's (CONTRACT.md, Stores, Capabilities): the
// guard's triggers refuse an unguarded agent write and write the ledger in
// the action's transaction, Postgres checks the signatures, a preview rolls
// back, writes compare xmin in the trigger, a person's change wins per row,
// foreign keys cascade, and Postgres keeps no before values itself (the
// ledger does).
var capabilities = action.Capabilities{
	InStoreEnforcement:    true,
	InStoreLedger:         true,
	InStoreSignatureCheck: true,
	TransactionalPreview:  true,
	ConditionalWrites:     true,
	TargetConflicts:       action.TargetRow,
	Cascades:              true,
	RetainsHistory:        false,
}

// Kind is POSTGRES.
func (*Store) Kind() action.StoreKind { return action.StorePostgres }

// Capabilities are Postgres's.
func (*Store) Capabilities() action.Capabilities { return capabilities }
