package store

import (
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// SQLSTATEs and names the mapping tells apart.
const (
	sqlStateQueryCanceled = "57014"
	sqlStateInsufficient  = "42501"
	sqlStateInvalidSchema = "3F000"
	sqlStateClassAuth     = "28"
	// sqlStateTooManyConnections is too_many_connections: the agent role is
	// at its CONNECTION LIMIT, checked by Postgres at login.
	sqlStateTooManyConnections = "53300"
	guardSchema                = "basalt_meta"
)

// guardCodes maps the guard's SQLSTATEs to contract codes. BS005 is split
// by message below.
var guardCodes = map[string]string{
	"BS001": action.CodeIntentRequired,
	"BS002": action.CodeApprovalRequired,
	"BS003": action.CodeRowLimitExceeded,
	"BS004": action.CodeStaleRead,
	"BS005": action.CodeApprovalInvalid,
	"BS006": action.CodeInternal,
	"BS007": action.CodeStatementRefused,
	"BS008": action.CodeInternal,
	"BS009": action.CodeNothingToRevert,
}

// messageCodes are guard codes, told apart by message within one SQLSTATE
// (BS005, BS009), that are also contract tool codes.
var messageCodes = []guardmodel.Code{
	guardmodel.CodeApprovalExpired, guardmodel.CodeRevertInvalid, guardmodel.CodeRevertExpired,
	guardmodel.CodeNothingToRevert,
}

// unavailableClasses are SQLSTATE classes meaning the database cannot serve
// the agent right now: connection exceptions, invalid authorization,
// insufficient resources, operator intervention other than a cancel.
var unavailableClasses = map[string]bool{"08": true, "28": true, "53": true, "57": true}

// MapError turns a Postgres failure into what the service reads: a
// *pgconn.PgError becomes an *action.StoreError with the contract's code
// and reason, a connection failure is marked action.ErrUnavailable, a
// message over the connection's cap action.ErrMessageTooLarge, and no row
// where one was expected action.ErrNotFound. Every other
// error, and nil, is returned as it is. The original stays in the chain.
func MapError(err error) error {
	var (
		se *action.StoreError
		pe *pgconn.PgError
		ce *pgconn.ConnectError
		me *pgproto3.ExceededMaxBodyLenErr
	)
	switch {
	case err == nil, errors.As(err, &se):
		return err
	case errors.As(err, &pe):
		return storeError(err, pe)
	case errors.As(err, &ce):
		return action.Unavailable(err)
	case errors.As(err, &me):
		return action.TooLarge(err)
	case errors.Is(err, pgx.ErrNoRows):
		return action.NotFound(err)
	}
	return err
}

// storeError is pe, found in err, as the contract's error.
func storeError(err error, pe *pgconn.PgError) *action.StoreError {
	se := &action.StoreError{
		Code: action.CodeStoreError, Message: pe.Message, StoreCode: pe.Code, Detail: pe.Detail, Hint: pe.Hint, Err: err,
	}
	gc, isGuard := guard.CodeOf(pe)
	if isGuard {
		se.LedgerCode = string(gc)
	}
	if code, ok := guardCodes[pe.Code]; ok {
		se.Code = code
		if pe.Detail != "" {
			// The guard's detail says what to fix (the stale row and its
			// versions, the missing intent); it names nothing secret.
			se.Message = pe.Message + ": " + pe.Detail
		}
		if pe.Hint != "" {
			se.Message += " (hint: " + pe.Hint + ")"
		}
		if isGuard && slices.Contains(messageCodes, gc) {
			se.Code = string(gc)
		}
		se.Reason = guardReason(se.Code, pe.Detail)
		return se
	}
	switch {
	case pe.Code == sqlStateQueryCanceled:
		se.Code, se.Reason = action.CodeQueryTimeout, action.ReasonTimeLimit
	case pe.Code == sqlStateInsufficient:
		se.Code = action.CodePermissionDenied
	case pe.Code == sqlStateInvalidSchema && strings.Contains(pe.Message, guardSchema):
		se.Code, se.Reason = action.CodeUnavailable, action.ReasonGuardMissing
	case len(pe.Code) == len(sqlStateQueryCanceled) && unavailableClasses[pe.Code[:2]]:
		se.Code, se.Reason = action.CodeUnavailable, unavailableReason(pe.Code)
	}
	return se
}

// unavailableReason tells a role at its connection limit (53300) and a
// refused credential (class 28) from a database the engine cannot reach.
func unavailableReason(sqlState string) string {
	if sqlState == sqlStateTooManyConnections {
		return action.ReasonTooManyConnections
	}
	if strings.HasPrefix(sqlState, sqlStateClassAuth) {
		return action.ReasonCredentialRejected
	}
	return action.ReasonDatabaseUnreachable
}

// guardReason is the catalog reason of a guard error, told apart by the
// guard's detail text (BS007, BS005).
func guardReason(code, detail string) string {
	switch code {
	case action.CodeStatementRefused:
		if strings.Contains(detail, "has no primary key") {
			return action.ReasonNoPrimaryKey
		}
		if detail == guardmodel.DetailHoldTooLarge {
			return action.ReasonHoldTooLarge
		}
		return action.ReasonNotAllowed
	case action.CodeApprovalInvalid:
		return detailReason(detail, approvalDetails, action.ReasonBadSignature)
	case action.CodeRevertInvalid:
		return detailReason(detail, revertDetails, action.ReasonBadSignature)
	}
	return ""
}

type detailRule struct{ contains, reason string }

// approvalDetails maps the guard's APPROVAL_INVALID details (BS005) to the
// catalog's reasons, first match wins; any other detail is a signature the
// guard did not accept.
var approvalDetails = []detailRule{
	{"unknown passkey", action.ReasonPasskeyRevoked},
	{"not approved yet", action.ReasonNotSigned},
	{"not signed for this agent", action.ReasonNotSigned},
	{"already used", action.ReasonAlreadyUsed},
	{"already signed", action.ReasonAlreadyUsed},
	{"another agent", action.ReasonNotThisAgent},
	{"no such approval", action.ReasonNotThisAgent},
	{"another run", action.ReasonDifferentWrite},
	{"differ from the approval", action.ReasonDifferentWrite},
	{"rows changed", action.ReasonRowsChanged},
	{"changes more than", action.ReasonRowsChanged},
}

// revertDetails is the same for REVERT_INVALID.
var revertDetails = []detailRule{
	{"line ", action.ReasonLineInvalid},
	{"a batch has", action.ReasonLineInvalid},
	{"the batch names", action.ReasonLineInvalid},
	{"no such revert", action.ReasonNotThisAgent},
	{"applied in one call", action.ReasonNotThisAgent},
	{"not signed this revert", action.ReasonPlanNotSigned},
	{"already applied", action.ReasonPlanFinished},
	{"already signed", action.ReasonPlanFinished},
	{"rows changed", action.ReasonRowsChanged},
}

func detailReason(detail string, rules []detailRule, fallback string) string {
	for _, r := range rules {
		if strings.Contains(detail, r.contains) {
			return r.reason
		}
	}
	return fallback
}
