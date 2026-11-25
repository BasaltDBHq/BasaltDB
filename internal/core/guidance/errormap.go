package guidance

import (
	"context"
	"errors"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// rowTooLargeHint ends a ROW_TOO_LARGE message with what to change: the
// agent reads a value whole or not at all.
const rowTooLargeHint = "; select fewer columns, a size (length(col), octet_length(col)) or a slice (substr(col, 1, 100000))"

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
		reason := ReasonSetupPending
		if se.Expired {
			reason = ReasonSetupExpired
		}
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reason, Message: se.Error()}
	case errors.As(err, &dn):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: ReasonDatabaseNotConfirmed, Message: dn.Error()}
	case errors.As(err, &ae):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: ae.Reason, Message: ae.Message}
	case sentinel(err, m.InvalidParams), sentinel(err, m.InvalidIntent):
		return &toolresult.ToolError{Code: CodeInvalidArgument, Reason: argumentReason(err), Message: err.Error()}
	case errors.As(err, &pe):
		return &toolresult.ToolError{Code: pe.Code, Reason: pe.Reason, Message: pe.Message, StoreCode: pe.StoreCode}
	case errors.Is(err, action.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: ReasonDatabaseUnreachable, Message: "the database cannot be reached"}
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

// DatabaseNotConfirmedError refuses a tool while the collected database
// waits for the person's confirmation (UNAVAILABLE DATABASE_NOT_CONFIRMED).
type DatabaseNotConfirmedError struct {
	SetupID  string
	Database setupcode.Address
}

func (e *DatabaseNotConfirmedError) Error() string {
	return "the agent's database waits for the person's confirmation; no tool but status and confirm_database works until then"
}

// sentinel reports whether err is target, false for a nil target. NewService
// refuses a Deps whose error values are nil, so the agent's own targets are
// set; the zero ErrorMap that classifies machine errors names none.
func sentinel(err, target error) bool { return target != nil && errors.Is(err, target) }
