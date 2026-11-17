package agent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/resultsize"
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
	ReasonSizeLimit       = "SIZE_LIMIT"
	ReasonRowTooLarge     = "ROW_TOO_LARGE"
	sqlStateQueryCanceled = "57014"
	sqlStateInsufficient  = "42501"
	sqlStateInvalidSchema = "3F000"
	sqlStateClassAuth     = "28"
	// sqlStateTooManyConnections is too_many_connections: the agent role is at
	// its CONNECTION LIMIT, checked by Postgres at login.
	sqlStateTooManyConnections = "53300"
	guardSchema                = "basalt_meta"

	ReasonStaleCursor  = "STALE_CURSOR"
	ReasonNoPrimaryKey = "NO_PRIMARY_KEY"
	ReasonNotAllowed   = "NOT_ALLOWED"
	// ReasonScopeFilter is a revert filter entry outside the agent's own
	// work, and ReasonScopeFilterCap a filter over revert.MaxFilter entries
	// (CONTRACT.md, Revert scope on preview_revert and request_revert).
	ReasonScopeFilter    = "SCOPE_FILTER"
	ReasonScopeFilterCap = "SCOPE_FILTER_CAP"
)

// guardCodes maps the guard's SQLSTATEs to contract
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
	// Reason is the catalog reason: STALE_CURSOR for a cursor that no longer
	// leads anywhere, SCOPE_FILTER or SCOPE_FILTER_CAP for a revert filter
	// refused, else none.
	Reason string
}

func (e *ArgumentError) Error() string { return e.Message }

// sizeLimitHint ends a SIZE_LIMIT message with what to change.
const sizeLimitHint = "; select fewer or shorter columns (for example left(col, 200)) or fewer rows"

// rowTooLargeHint ends a ROW_TOO_LARGE message with what to change: the
// agent reads a value whole or not at all.
const rowTooLargeHint = "; select fewer columns, a size (length(col), octet_length(col)) or a slice (substr(col, 1, 100000))"

// sizeLimitError is QUERY_TIMEOUT SIZE_LIMIT: a result over
// agentdb.MaxResultBytes.
func sizeLimitError() *mcp.ToolError {
	return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonSizeLimit, Message: agentdb.ErrSizeLimit.Error() + sizeLimitHint}
}

// messageTooLarge maps a Postgres message over the agent connection's cap
// (pgx MaxProtocolMessageBodyLen: one row too large to read) to SIZE_LIMIT
// for a tool that declares QUERY_TIMEOUT. Any other tool read the row from
// the guard's own tables, so it stays the INTERNAL error ToolError made.
func messageTooLarge(tool string, err error, te *mcp.ToolError) *mcp.ToolError {
	var me *pgproto3.ExceededMaxBodyLenErr
	if !errors.As(err, &me) || !declares(tool, CodeQueryTimeout) {
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
func ToolError(err error) *mcp.ToolError {
	var (
		te *mcp.ToolError
		re *sqlguard.RefusalError
		ae *ArgumentError
		pe *pgconn.PgError
		se *SetupError
		ce *pgconn.ConnectError
		rl *resultsize.RowTooLargeError
	)
	switch {
	case errors.As(err, &te):
		return te
	case errors.As(err, &re):
		return &mcp.ToolError{Code: CodeStatementRefused, Reason: string(re.Reason), Message: re.Error()}
	case errors.Is(err, action.ErrRowLimit):
		return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowLimit, Message: err.Error() + "; add a LIMIT or a narrower WHERE"}
	case errors.As(err, &rl):
		return &mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonRowTooLarge, Message: rl.Error() + rowTooLargeHint}
	case errors.Is(err, agentdb.ErrSizeLimit):
		return sizeLimitError()
	case errors.As(err, &se):
		reason := reasonSetupPending
		if se.Expired {
			reason = reasonSetupExpired
		}
		return &mcp.ToolError{Code: CodeUnavailable, Reason: reason, Message: se.Error()}
	case errors.As(err, &ae):
		return &mcp.ToolError{Code: CodeInvalidArgument, Reason: ae.Reason, Message: ae.Message}
	case errors.Is(err, ledger.ErrInvalidParams), errors.Is(err, guard.ErrInvalidIntent):
		return &mcp.ToolError{Code: CodeInvalidArgument, Reason: argumentReason(err), Message: err.Error()}
	case errors.As(err, &pe):
		return pgToolError(pe)
	case errors.As(err, &ce), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return &mcp.ToolError{Code: CodeUnavailable, Reason: reasonDatabaseUnreachable, Message: "the database cannot be reached"}
	}
	return &mcp.ToolError{Code: CodeInternal, Message: "internal engine error"}
}

// argumentReason is STALE_CURSOR for a list cursor the engine cannot read
// (kept from an earlier page or another list), else no reason.
func argumentReason(err error) string {
	if strings.Contains(err.Error(), "invalid cursor") {
		return ReasonStaleCursor
	}
	return ""
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
		if pe.Hint != "" {
			te.Message += " (hint: " + pe.Hint + ")"
		}
		if gc, ok := guard.CodeOf(pe); ok && slices.Contains(messageCodes, gc) {
			te.Code = string(gc)
		}
		te.Reason = guardReason(te.Code, pe.Detail)
		return te
	}
	switch {
	case pe.Code == sqlStateQueryCanceled:
		te.Code, te.Reason = CodeQueryTimeout, ReasonTimeLimit
	case pe.Code == sqlStateInsufficient:
		te.Code = CodePermissionDenied
	case pe.Code == sqlStateInvalidSchema && strings.Contains(pe.Message, guardSchema):
		te.Code, te.Reason = CodeUnavailable, reasonGuardMissing
	case len(pe.Code) == len(sqlStateQueryCanceled) && unavailableClasses[pe.Code[:2]]:
		te.Code, te.Reason = CodeUnavailable, unavailableReason(pe.Code)
	}
	return te
}

// unavailableReason tells a role at its connection limit (53300) and a
// refused credential (class 28) from a database the engine cannot reach.
func unavailableReason(sqlState string) string {
	if sqlState == sqlStateTooManyConnections {
		return reasonTooManyConnections
	}
	if strings.HasPrefix(sqlState, sqlStateClassAuth) {
		return reasonCredentialRejected
	}
	return reasonDatabaseUnreachable
}

// guardReason is the catalog reason of a guard error, told apart by the
// guard's detail text (BS007, BS005).
func guardReason(code, detail string) string {
	switch code {
	case CodeStatementRefused:
		if strings.Contains(detail, "has no primary key") {
			return ReasonNoPrimaryKey
		}
		if detail == guard.DetailHoldTooLarge {
			return ReasonHoldTooLarge
		}
		return ReasonNotAllowed
	case CodeApprovalInvalid:
		return detailReason(detail, approvalDetails, reasonBadSignature)
	case CodeRevertInvalid:
		return detailReason(detail, revertDetails, reasonBadSignature)
	}
	return ""
}

type detailRule struct{ contains, reason string }

// approvalDetails maps the guard's APPROVAL_INVALID details (BS005) to the
// catalog's reasons, first match wins; any other detail is a signature the
// guard did not accept.
var approvalDetails = []detailRule{
	{"unknown passkey", reasonPasskeyRevoked},
	{"not approved yet", reasonNotSigned},
	{"not signed for this agent", reasonNotSigned},
	{"already used", reasonAlreadyUsed},
	{"already signed", reasonAlreadyUsed},
	{"another agent", reasonNotThisAgent},
	{"no such approval", reasonNotThisAgent},
	{"another run", reasonDifferentWrite},
	{"differ from the approval", reasonDifferentWrite},
	{"rows changed", reasonRowsChanged},
	{"changes more than", reasonRowsChanged},
}

// revertDetails is the same for REVERT_INVALID.
var revertDetails = []detailRule{
	{"line ", reasonLineInvalid},
	{"a batch has", reasonLineInvalid},
	{"the batch names", reasonLineInvalid},
	{"no such revert", reasonNotThisAgent},
	{"applied in one call", reasonNotThisAgent},
	{"not signed this revert", reasonPlanNotSigned},
	{"already applied", reasonPlanFinished},
	{"already signed", reasonPlanFinished},
	{"rows changed", reasonRowsChanged},
}

func detailReason(detail string, rules []detailRule, fallback string) string {
	for _, r := range rules {
		if strings.Contains(detail, r.contains) {
			return r.reason
		}
	}
	return fallback
}
