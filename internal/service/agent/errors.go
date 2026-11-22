package agent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// Error codes (CONTRACT.md, "Error codes"). The ones a store answers with
// are action's.
const (
	CodeIntentRequired   = action.CodeIntentRequired
	CodeStaleRead        = action.CodeStaleRead
	CodeStatementRefused = action.CodeStatementRefused
	CodeRowLimitExceeded = action.CodeRowLimitExceeded
	CodeQueryTimeout     = action.CodeQueryTimeout
	CodeApprovalRequired = action.CodeApprovalRequired
	CodeApprovalExpired  = action.CodeApprovalExpired
	CodeApprovalInvalid  = action.CodeApprovalInvalid
	CodeNothingToRevert  = action.CodeNothingToRevert
	CodeRevertInvalid    = action.CodeRevertInvalid
	CodeRevertExpired    = action.CodeRevertExpired
	CodePermissionDenied = action.CodePermissionDenied
	CodeNotFound         = "NOT_FOUND"
	CodeSQLError         = action.CodeSQLError
	CodeInvalidArgument  = "INVALID_ARGUMENT"
	CodeUnavailable      = action.CodeUnavailable
	CodeInternal         = action.CodeInternal
	ReasonTimeLimit      = action.ReasonTimeLimit
	ReasonRowLimit       = "ROW_LIMIT"
	ReasonSizeLimit      = "SIZE_LIMIT"
	ReasonRowTooLarge    = "ROW_TOO_LARGE"

	ReasonStaleCursor  = "STALE_CURSOR"
	ReasonNoPrimaryKey = action.ReasonNoPrimaryKey
	ReasonNotAllowed   = action.ReasonNotAllowed
	// ReasonScopeFilter is a revert filter entry outside the agent's own
	// work, and ReasonScopeFilterCap a filter over revert.MaxFilter entries
	// (CONTRACT.md, Revert scope on preview_revert and request_revert).
	ReasonScopeFilter    = "SCOPE_FILTER"
	ReasonScopeFilterCap = "SCOPE_FILTER_CAP"
)

// ArgumentError is a tool call whose arguments fail validation.
type ArgumentError struct {
	Message string
	// Reason is the catalog reason: STALE_CURSOR for a cursor that no longer
	// leads anywhere, SCOPE_FILTER or SCOPE_FILTER_CAP for a revert filter
	// refused, ADMIN_CREDENTIAL for a connection string with a password,
	// else none.
	Reason string
}

func (e *ArgumentError) Error() string { return e.Message }

// sizeLimitHint ends a SIZE_LIMIT message with what to change.
const sizeLimitHint = "; select fewer or shorter columns (for example left(col, 200)) or fewer rows"

// rowTooLargeHint ends a ROW_TOO_LARGE message with what to change: the
// agent reads a value whole or not at all.
const rowTooLargeHint = "; select fewer columns, a size (length(col), octet_length(col)) or a slice (substr(col, 1, 100000))"

// sizeLimitError is QUERY_TIMEOUT SIZE_LIMIT: a result over
// budget.MaxBytes.
func sizeLimitError() *toolresult.ToolError {
	return &toolresult.ToolError{Code: CodeQueryTimeout, Reason: ReasonSizeLimit, Message: budget.ErrSizeLimit.Error() + sizeLimitHint}
}

// messageTooLarge maps a Postgres message over the agent connection's cap
// (pgx MaxProtocolMessageBodyLen: one row too large to read) to SIZE_LIMIT
// for a tool that declares QUERY_TIMEOUT. Any other tool read the row from
// the guard's own tables, so it stays the INTERNAL error ToolError made.
func messageTooLarge(tool string, err error, te *toolresult.ToolError) *toolresult.ToolError {
	if !errors.Is(err, action.ErrMessageTooLarge) || !declares(tool, CodeQueryTimeout) {
		return te
	}
	return sizeLimitError()
}

// toolContracts are the tool contracts, loaded once.
var toolContracts = sync.OnceValue(mcpcontract.MustLoad)

// declares reports whether tool's contract lists code among its errors.
func declares(tool, code string) bool {
	c, ok := mcpcontract.Find(toolContracts(), tool)
	return ok && slices.Contains(c.Errors, code)
}

// ToolError maps any error from a tool's service call to the contract's
// error body. Unexpected errors become INTERNAL without their text, which can
// name hosts or roles; the caller logs the original.
func ToolError(err error) *toolresult.ToolError {
	var (
		te *toolresult.ToolError
		re *action.RefusalError
		ae *ArgumentError
		pe *action.StoreError
		se *SetupError
		dn *DatabaseNotConfirmedError
	)
	switch {
	case errors.As(err, &te):
		return te
	case errors.As(err, &re):
		return &toolresult.ToolError{Code: CodeStatementRefused, Reason: string(re.Reason), Message: re.Error()}
	case errors.Is(err, action.ErrRowLimit):
		return &toolresult.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowLimit, Message: err.Error() + "; add a LIMIT or a narrower WHERE"}
	case isRowTooLarge(err):
		return &toolresult.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowTooLarge, Message: rowTooLargeMessage(err) + rowTooLargeHint}
	case errors.Is(err, budget.ErrSizeLimit):
		return sizeLimitError()
	case errors.As(err, &se):
		reason := reasonSetupPending
		if se.Expired {
			reason = reasonSetupExpired
		}
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reason, Message: se.Error()}
	case errors.As(err, &dn):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reasonDatabaseNotConfirmed, Message: dn.Error()}
	case errors.As(err, &ae):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: ae.Reason, Message: ae.Message}
	case sentinel(err, theHost().ErrInvalidParams), sentinel(err, theHost().ErrInvalidIntent):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: argumentReason(err), Message: err.Error()}
	case errors.As(err, &pe):
		return &toolresult.ToolError{Code: pe.Code, Reason: pe.Reason, Message: pe.Message, SQLState: pe.SQLState}
	case errors.Is(err, action.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reasonDatabaseUnreachable, Message: "the database cannot be reached"}
	}
	return &toolresult.ToolError{Code: CodeInternal, Message: "internal engine error"}
}

// isRowTooLarge reports whether err is one row over the result budget on
// its own; rowTooLargeMessage is its message.
func isRowTooLarge(err error) bool {
	_, ok := theHost().RowTooLarge(err)
	return ok
}

func rowTooLargeMessage(err error) string {
	msg, _ := theHost().RowTooLarge(err)
	return msg
}

// argumentReason is STALE_CURSOR for a list cursor the engine cannot read
// (kept from an earlier page or another list), else no reason.
func argumentReason(err error) string {
	if strings.Contains(err.Error(), "invalid cursor") {
		return ReasonStaleCursor
	}
	return ""
}

// storeError is the store's error in err's chain, nil when there is none.
func storeError(err error) *action.StoreError {
	var se *action.StoreError
	if !errors.As(err, &se) {
		return nil
	}
	return se
}

// ledgerCode is the ledger's code of a refusal the store answered (the
// guard's code for Postgres), and false for any other error.
func ledgerCode(err error) (guardmodel.Code, bool) {
	se := storeError(err)
	if se == nil || se.LedgerCode == "" {
		return "", false
	}
	return guardmodel.Code(se.LedgerCode), true
}

// storeDetail is the detail of the store's error in err, "" when none.
func storeDetail(err error) string {
	if se := storeError(err); se != nil {
		return se.Detail
	}
	return ""
}

// scopeRefusal returns the detail (guardmodel.ScopeShape, ScopeNotOwnRun, ...)
// and the explanation of a SCOPE_REFUSED error, and false for any other
// error.
func scopeRefusal(err error) (detail, hint string, ok bool) {
	se := storeError(err)
	if se == nil || se.LedgerCode != string(guardmodel.CodeScopeRefused) {
		return "", "", false
	}
	return se.Detail, se.Hint, true
}

// timedOut reports whether the store canceled the statement at its time
// limit (QUERY_TIMEOUT TIME_LIMIT).
func timedOut(err error) bool {
	se := storeError(err)
	return se != nil && se.Code == CodeQueryTimeout && se.Reason == ReasonTimeLimit
}
