package action

// Error codes and reasons a store can answer with (CONTRACT.md, Error
// codes; api/mcp/errors/next-steps.json). They are contract enums: a store
// adapter maps its own failures to them, and the agent's tools return them
// as they are.
const (
	CodeIntentRequired   = "INTENT_REQUIRED"
	CodeStaleRead        = "STALE_READ"
	CodeStatementRefused = "STATEMENT_REFUSED"
	CodeRowLimitExceeded = "ROW_LIMIT_EXCEEDED"
	CodeQueryTimeout     = "QUERY_TIMEOUT"
	CodeApprovalRequired = "APPROVAL_REQUIRED"
	CodeApprovalExpired  = "APPROVAL_EXPIRED"
	CodeApprovalInvalid  = "APPROVAL_INVALID"
	CodeNothingToRevert  = "NOTHING_TO_REVERT"
	CodeRevertInvalid    = "REVERT_INVALID"
	CodeRevertExpired    = "REVERT_EXPIRED"
	CodePermissionDenied = "PERMISSION_DENIED"
	CodeStoreError       = "STORE_ERROR"
	CodeUnavailable      = "UNAVAILABLE"
	CodeInternal         = "INTERNAL"
)

// Reasons of the codes above that a store tells apart.
const (
	ReasonTimeLimit           = "TIME_LIMIT"
	ReasonNoPrimaryKey        = "NO_PRIMARY_KEY"
	ReasonNotAllowed          = "NOT_ALLOWED"
	ReasonHoldTooLarge        = "HOLD_TOO_LARGE"
	ReasonDatabaseUnreachable = "DATABASE_UNREACHABLE"
	ReasonTooManyConnections  = "TOO_MANY_CONNECTIONS"
	ReasonCredentialRejected  = "CREDENTIAL_REJECTED" //nolint:gosec // a catalog reason, not a credential
	ReasonGuardMissing        = "GUARD_MISSING"
	ReasonAlreadyUsed         = "ALREADY_USED"
	ReasonDifferentWrite      = "DIFFERENT_WRITE"
	ReasonNotThisAgent        = "NOT_THIS_AGENT"
	ReasonLineInvalid         = "LINE_INVALID"
	ReasonPlanNotSigned       = "PLAN_NOT_SIGNED"
	ReasonBadSignature        = "BAD_SIGNATURE"
	ReasonPasskeyRevoked      = "PASSKEY_REVOKED"
	ReasonRowsChanged         = "ROWS_CHANGED"
	ReasonPlanFinished        = "PLAN_FINISHED"
	ReasonNotSigned           = "NOT_SIGNED"
	// ReasonRevealRefused is every refused reveal proof, key, nonce or
	// ticket (APPROVAL_INVALID and REVERT_INVALID, pages API only).
	ReasonRevealRefused = "REVEAL_REFUSED"
)
