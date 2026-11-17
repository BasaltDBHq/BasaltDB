package action

// Op is the kind of statement an action runs.
type Op string

// The ops of a statement. OpOther is the op a refusal is recorded with when
// the statement is not one of the four the ledger records by name.
const (
	OpSelect Op = "SELECT"
	OpInsert Op = "INSERT"
	OpUpdate Op = "UPDATE"
	OpDelete Op = "DELETE"
	OpMerge  Op = "MERGE"
	OpOther  Op = "OTHER"
)

// Statement is a checked statement as the service sees it: its op, the
// tables it names, and an opaque handle the store reads back when it runs
// the statement. The service never inspects Handle.
type Statement struct {
	Op Op
	// Tables are the relations the statement names, as written, sorted.
	Tables []string
	// Handle is the store's own data about the statement (for Postgres, the
	// relations whose row versions a read can return); nil when it has
	// none.
	Handle any
}
