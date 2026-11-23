package agentkit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"

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

// SizeLimitError is QUERY_TIMEOUT SIZE_LIMIT: a result over
// budget.MaxBytes.
func SizeLimitError() *toolresult.ToolError {
	return &toolresult.ToolError{Code: CodeQueryTimeout, Reason: ReasonSizeLimit, Message: budget.ErrSizeLimit.Error() + sizeLimitHint}
}

// MessageTooLarge maps a Postgres message over the agent connection's cap
// (pgx MaxProtocolMessageBodyLen: one row too large to read) to SIZE_LIMIT
// for a tool that declares QUERY_TIMEOUT. Any other tool read the row from
// the guard's own tables, so it stays the INTERNAL error ToolError made.
func MessageTooLarge(tool string, err error, te *toolresult.ToolError) *toolresult.ToolError {
	if !errors.Is(err, action.ErrMessageTooLarge) || !declares(tool, CodeQueryTimeout) {
		return te
	}
	return SizeLimitError()
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
func (m ErrorMap) ToolError(err error) *toolresult.ToolError {
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
	case m.isRowTooLarge(err):
		return &toolresult.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowTooLarge, Message: m.rowTooLargeMessage(err) + rowTooLargeHint}
	case errors.Is(err, budget.ErrSizeLimit):
		return SizeLimitError()
	case errors.As(err, &se):
		reason := guidance.ReasonSetupPending
		if se.Expired {
			reason = guidance.ReasonSetupExpired
		}
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reason, Message: se.Error()}
	case errors.As(err, &dn):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: guidance.ReasonDatabaseNotConfirmed, Message: dn.Error()}
	case errors.As(err, &ae):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: ae.Reason, Message: ae.Message}
	case Sentinel(err, m.InvalidParams), Sentinel(err, m.InvalidIntent):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: argumentReason(err), Message: err.Error()}
	case errors.As(err, &pe):
		return &toolresult.ToolError{Code: pe.Code, Reason: pe.Reason, Message: pe.Message, SQLState: pe.SQLState}
	case errors.Is(err, action.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: guidance.ReasonDatabaseUnreachable, Message: "the database cannot be reached"}
	}
	return &toolresult.ToolError{Code: CodeInternal, Message: "internal engine error"}
}

// isRowTooLarge reports whether err is one row over the result budget on
// its own; rowTooLargeMessage is its message.
func (m ErrorMap) isRowTooLarge(err error) bool {
	if m.RowTooLarge == nil {
		return false
	}
	_, ok := m.RowTooLarge(err)
	return ok
}

func (m ErrorMap) rowTooLargeMessage(err error) string {
	if m.RowTooLarge == nil {
		return ""
	}
	msg, _ := m.RowTooLarge(err)
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

// StoreError is the store's error in err's chain, nil when there is none.
func StoreError(err error) *action.StoreError {
	var se *action.StoreError
	if !errors.As(err, &se) {
		return nil
	}
	return se
}

// LedgerCode is the ledger's code of a refusal the store answered (the
// guard's code for Postgres), and false for any other error.
func LedgerCode(err error) (guardmodel.Code, bool) {
	se := StoreError(err)
	if se == nil || se.LedgerCode == "" {
		return "", false
	}
	return guardmodel.Code(se.LedgerCode), true
}

// StoreDetail is the detail of the store's error in err, "" when none.
func StoreDetail(err error) string {
	if se := StoreError(err); se != nil {
		return se.Detail
	}
	return ""
}

// ScopeRefusal returns the detail (guardmodel.ScopeShape, ScopeNotOwnRun, ...)
// and the explanation of a SCOPE_REFUSED error, and false for any other
// error.
func ScopeRefusal(err error) (detail, hint string, ok bool) {
	se := StoreError(err)
	if se == nil || se.LedgerCode != string(guardmodel.CodeScopeRefused) {
		return "", "", false
	}
	return se.Detail, se.Hint, true
}

// TimedOut reports whether the store canceled the statement at its time
// limit (QUERY_TIMEOUT TIME_LIMIT).
func TimedOut(err error) bool {
	se := StoreError(err)
	return se != nil && se.Code == CodeQueryTimeout && se.Reason == ReasonTimeLimit
}

// ErrorMap holds the error values of the adapters the agent tells apart to
// map a failure to the contract's tool error. A nil value matches nothing.
type ErrorMap struct {
	// InvalidParams is the ledger's, InvalidIntent the guard's: values the
	// agent maps to INVALID_ARGUMENT.
	InvalidParams error
	InvalidIntent error
	// RowTooLarge says whether err is one row over the result budget on its
	// own, with its message.
	RowTooLarge func(err error) (message string, ok bool)
}

// SetupError is a call refused because the agent's setup from the laptop has
// not run (CONTRACT.md, Setup from your laptop). Code is the pending setup
// code, which the person runs on their own computer, and Fingerprint the
// one it shows; Expired when it ran out.
type SetupError struct {
	Code        string
	Fingerprint string
	Expired     bool
	// ConnectOnly: the pending code is connect-only, so status's setup
	// problem says what comes next (CONTRACT.md, Next steps for a
	// connect-only code).
	ConnectOnly bool
}

func (e *SetupError) Error() string {
	if e.Expired {
		return "the agent's setup code expired before it was used"
	}
	return "the agent's setup has not run yet"
}

// DatabaseNotConfirmedError refuses a tool while the collected database
// waits for the person's confirmation (UNAVAILABLE DATABASE_NOT_CONFIRMED).
type DatabaseNotConfirmedError struct {
	SetupID  string
	Database setupcode.Address
}

func (e *DatabaseNotConfirmedError) Error() string {
	return "the agent's database waits for the person's confirmation; no tool but status and confirm_database works until then"
}

// Sentinel reports whether err is target, false for a nil target. NewService
// refuses a Deps whose error values are nil, so the agent's own targets are
// set; the zero ErrorMap that classifies machine errors names none.
func Sentinel(err, target error) bool { return target != nil && errors.Is(err, target) }

// PersonTime is how a person-facing message states a deadline.
const PersonTime = "2006-01-02 15:04 UTC"

// PageError is an answer meant for the revert page as it is: the pages
// answer it without the agent's catalog, since no agent tool returns it.
// RescopeNonce, when set, goes in the page's error body: the nonce of the
// widen the page asks the person for.
type PageError struct {
	*toolresult.ToolError
	RescopeNonce passkey.Bytes
}

func (e *PageError) Unwrap() error { return e.ToolError }
