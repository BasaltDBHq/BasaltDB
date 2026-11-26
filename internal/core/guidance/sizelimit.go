package guidance

import (
	"errors"
	"slices"
	"sync"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// sizeLimitHint ends a SIZE_LIMIT message with what to change.
const sizeLimitHint = "; select fewer or shorter columns (for example left(col, 200)) or fewer rows"

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
