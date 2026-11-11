package agent

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// Error codes (CONTRACT.md, "Error codes").
const (
	CodeIntentRequired    = "INTENT_REQUIRED"
	CodeStaleRead         = "STALE_READ"
	CodeStatementRefused  = "STATEMENT_REFUSED"
	CodeRowLimitExceeded  = "ROW_LIMIT_EXCEEDED"
	CodeQueryTimeout      = "QUERY_TIMEOUT"
	CodeApprovalRequired  = "APPROVAL_REQUIRED"
	CodeApprovalExpired   = "APPROVAL_EXPIRED"
	CodeApprovalInvalid   = "APPROVAL_INVALID"
	CodeNothingToRevert   = "NOTHING_TO_REVERT"
	CodeRevertInvalid     = "REVERT_INVALID"
	CodeRevertExpired     = "REVERT_EXPIRED"
	CodePermissionDenied  = "PERMISSION_DENIED"
	CodeNotFound          = "NOT_FOUND"
	CodeSQLError          = "SQL_ERROR"
	CodeInvalidArgument   = "INVALID_ARGUMENT"
	CodeUnavailable       = "UNAVAILABLE"
	CodeInternal          = "INTERNAL"
	ReasonTimeLimit       = "TIME_LIMIT"
	ReasonRowLimit        = "ROW_LIMIT"
	sqlStateQueryCanceled = "57014"
	sqlStateInsufficient  = "42501"
)

// guardCodes maps the guard's SQLSTATEs (M0 spike, section 2) to contract
// codes. BS005 is split by message below.
var guardCodes = map[string]string{
	"BS001": CodeIntentRequired,
	"BS002": CodeApprovalRequired,
	"BS003": CodeRowLimitExceeded,
	"BS004": CodeStaleRead,
	"BS005": CodeApprovalInvalid,
	"BS006": CodeInternal,
	"BS007": CodeStatementRefused,
	"BS008": CodeInternal,
	"BS009": CodeNothingToRevert,
}

// messageCodes are guard codes, told apart by message within one SQLSTATE
// (BS005, BS009), that are also contract tool codes.
var messageCodes = []guard.Code{
	guard.CodeApprovalExpired, guard.CodeRevertInvalid, guard.CodeRevertExpired,
	guard.CodeNothingToRevert,
}

// unavailableClasses are SQLSTATE classes meaning the database cannot serve
// the agent right now: connection exceptions, invalid authorization,
// insufficient resources, operator intervention other than a cancel.
var unavailableClasses = map[string]bool{"08": true, "28": true, "53": true, "57": true}

// ArgumentError is a tool call whose arguments fail validation.
type ArgumentError struct {
	Message string
}

func (e *ArgumentError) Error() string { return e.Message }

// ToolError maps any error from a tool's service call to the contract's
// error body. Unexpected errors become INTERNAL without their text, which can
// name hosts or roles; the caller logs the original.
func ToolError(err error) *mcp.ToolError {
	var (
		te *mcp.ToolError
		re *sqlguard.RefusalError
		ae *ArgumentError
		pe *pgconn.PgError
		ce *pgconn.ConnectError
	)
	switch {
	case errors.As(err, &te):
		return te
	case errors.As(err, &re):
		return &mcp.ToolError{Code: CodeStatementRefused, Reason: string(re.Reason), Message: re.Error()}
	case errors.Is(err, agentdb.ErrRowLimit):
		return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowLimit, Message: err.Error() + "; add a LIMIT or a narrower WHERE"}
	case errors.As(err, &ae):
		return &mcp.ToolError{Code: CodeInvalidArgument, Message: ae.Message}
	case errors.Is(err, ledger.ErrInvalidParams), errors.Is(err, guard.ErrInvalidIntent):
		return &mcp.ToolError{Code: CodeInvalidArgument, Message: err.Error()}
	case errors.As(err, &pe):
		return pgToolError(pe)
	case errors.As(err, &ce), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &mcp.ToolError{Code: CodeUnavailable, Message: "the database cannot be reached"}
	}
	return &mcp.ToolError{Code: CodeInternal, Message: "internal engine error"}
}

func pgToolError(pe *pgconn.PgError) *mcp.ToolError {
	te := &mcp.ToolError{Code: CodeSQLError, Message: pe.Message, SQLState: pe.Code}
	if code, ok := guardCodes[pe.Code]; ok {
		te.Code = code
		if pe.Detail != "" {
			// The guard's detail says what to fix (the stale row and its
			// versions, the missing intent); it names nothing secret.
			te.Message = pe.Message + ": " + pe.Detail
		}
		if gc, ok := guard.CodeOf(pe); ok && slices.Contains(messageCodes, gc) {
			te.Code = string(gc)
		}
		return te
	}
	switch {
	case pe.Code == sqlStateQueryCanceled:
		te.Code, te.Reason = CodeQueryTimeout, ReasonTimeLimit
	case pe.Code == sqlStateInsufficient:
		te.Code = CodePermissionDenied
	case len(pe.Code) == len(sqlStateQueryCanceled) && unavailableClasses[pe.Code[:2]]:
		te.Code = CodeUnavailable
	}
	return te
}
