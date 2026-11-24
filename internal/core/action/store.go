package action

// StoreKind is the kind of system an agent's actions land in (CONTRACT.md,
// Stores).
type StoreKind string

// The store kinds. Only StorePostgres is served; the others are designed.
const (
	StorePostgres StoreKind = "POSTGRES"
	StoreMySQL    StoreKind = "MYSQL"
	StoreS3       StoreKind = "S3"
	StoreDrive    StoreKind = "DRIVE"
)

// TargetUnit is the unit a person's change wins over an agent's.
type TargetUnit string

// The target units.
const (
	TargetRow TargetUnit = "ROW"
)

// Capabilities are what the engine may rely on for a store (CONTRACT.md,
// Stores, Capabilities).
type Capabilities struct {
	// InStoreEnforcement: the store refuses an unguarded agent write.
	InStoreEnforcement bool
	// InStoreLedger: the ledger is written in the action's own transaction.
	InStoreLedger bool
	// InStoreSignatureCheck: the store verifies an approval's signature.
	InStoreSignatureCheck bool
	// TransactionalPreview: a trial run that rolls back.
	TransactionalPreview bool
	// ConditionalWrites: compare-and-set on the version.
	ConditionalWrites bool
	// TargetConflicts is the unit a person's change wins over an agent's.
	TargetConflicts TargetUnit
	// Cascades: a write reaches targets the action did not name.
	Cascades bool
	// RetainsHistory: the store itself keeps before values.
	RetainsHistory bool
}
