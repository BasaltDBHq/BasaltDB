package action

// Tool is the tool a statement is checked for: query runs only reads,
// write everything else.
type Tool string

// The tools a statement is checked for.
const (
	ToolQuery Tool = "QUERY"
	ToolWrite Tool = "WRITE"
)

// RefusalReason is why a statement was refused before it reached the store
// (STATEMENT_REFUSED's reason; CONTRACT.md, Error codes).
type RefusalReason string

// The refusal reasons a store's check can give. They are contract enums
// (CONTRACT.md, Error codes), so they stay here in core even where only a
// SQL store gives them: SELECT_INTO, LOCKING_READ, MERGE_NOT_ALLOWED and
// DATA_MODIFYING_WITH name SQL statements.
const (
	ReasonParseError         RefusalReason = "PARSE_ERROR"
	ReasonMultipleStatements RefusalReason = "MULTIPLE_STATEMENTS"
	ReasonWrongTool          RefusalReason = "WRONG_TOOL"
	ReasonDDL                RefusalReason = "DDL_NOT_ALLOWED"
	ReasonUtility            RefusalReason = "STATEMENT_NOT_ALLOWED"
	ReasonSelectInto         RefusalReason = "SELECT_INTO"
	ReasonLockingRead        RefusalReason = "LOCKING_READ"
	ReasonMerge              RefusalReason = "MERGE_NOT_ALLOWED"
	ReasonDataModifyingWith  RefusalReason = "DATA_MODIFYING_WITH"
	ReasonFunction           RefusalReason = "FUNCTION_NOT_ALLOWED"
	ReasonNotRepeatable      RefusalReason = "NOT_REPEATABLE"
)

// RefusalError is a statement the store's check refused.
type RefusalError struct {
	Reason RefusalReason
	Detail string
}

func (r *RefusalError) Error() string {
	if r.Detail == "" {
		return string(r.Reason)
	}
	return string(r.Reason) + ": " + r.Detail
}
