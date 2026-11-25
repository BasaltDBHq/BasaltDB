package action

// Op is the kind of statement an action runs.
type Op string

// The ops of a statement. OpOther is the op a refusal is recorded with when
// the statement is not one of the four the ledger records by name.
const (
	OpRead   Op = "READ"
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
	// ParamCount is the highest $n placeholder used, 0 when none.
	ParamCount int
	// Handle is the store's own data about the statement (for Postgres, the
	// relations whose row versions a read can return); nil when it has
	// none.
	Handle any
}

// Request is one request in the store's language: its text and its
// parameters (agentstore.Request is the same type). Services pass it on and
// record it, and never read Text. Postgres: SQL text with $n parameters.
type Request struct {
	Text   string
	Params []any
}
