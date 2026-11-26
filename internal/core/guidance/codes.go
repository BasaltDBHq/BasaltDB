package guidance

import (
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
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
	CodeStoreError       = action.CodeStoreError
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

// PersonTime is how a person-facing message states a deadline.
const PersonTime = "2006-01-02 15:04 UTC"

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

// SetupError is a call refused because the agent's setup has not run
// (CONTRACT.md, Setup). Code is the pending setup code, which the person
// runs on the connect page, and Fingerprint the one it shows; Expired when
// it ran out.
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

// PageError is an answer meant for the revert page as it is: the pages
// answer it without the agent's catalog, since no agent tool returns it.
// RescopeNonce, when set, goes in the page's error body: the nonce of the
// widen the page asks the person for.
type PageError struct {
	*toolresult.ToolError
	RescopeNonce passkey.Bytes
}

func (e *PageError) Unwrap() error { return e.ToolError }
