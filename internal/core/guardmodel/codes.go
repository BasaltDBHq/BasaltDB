package guardmodel

// Code is a guard error code. Values match the MESSAGE the guard raises and
// the CONTRACT.md tool error codes where one exists.
type Code string

// Guard error codes (SQLSTATE class BS).
const (
	CodeIntentRequired      Code = "INTENT_REQUIRED"       // BS001
	CodeApprovalRequired    Code = "APPROVAL_REQUIRED"     // BS002
	CodeRowLimitExceeded    Code = "ROW_LIMIT_EXCEEDED"    // BS003
	CodeStaleRead           Code = "STALE_READ"            // BS004
	CodeApprovalInvalid     Code = "APPROVAL_INVALID"      // BS005
	CodeApprovalExpired     Code = "APPROVAL_EXPIRED"      // BS005
	CodePreviewCannotCommit Code = "PREVIEW_CANNOT_COMMIT" // BS006
	CodeNotAllowed          Code = "NOT_ALLOWED"           // BS007
	CodeLedgerInputInvalid  Code = "LEDGER_INPUT_INVALID"  // BS008
	CodeRevertInvalid       Code = "REVERT_INVALID"        // BS005
	CodeRevertExpired       Code = "REVERT_EXPIRED"        // BS005
	CodeNothingToRevert     Code = "NOTHING_TO_REVERT"     // BS009
	CodeRevertCascade       Code = "REVERT_CASCADE"        // BS009, caught inside a revert
	CodeSetupRefused        Code = "SETUP_REFUSED"         // BS010, to the admin only
	CodeScopeRefused        Code = "SCOPE_REFUSED"         // BS011
)

// Details of SCOPE_REFUSED (BS011): why a revert scope descriptor was
// refused (CONTRACT.md, Guard errors).
const (
	ScopeShape         = "SHAPE"
	ScopeStoreReserved = "STORE_RESERVED"
	ScopeFilterCap     = "FILTER_CAP"
	ScopeNotOwnChange  = "NOT_OWN_CHANGE"
	ScopeNotOwnRun     = "NOT_OWN_RUN"
	ScopeNotOwnTask    = "NOT_OWN_TASK"
	ScopeFilter        = "FILTER"
	// ScopeDescriptor is a rescope_revert select whose scope, or a listed
	// agent, lies outside what the revert can cover (version 21).
	ScopeDescriptor = "DESCRIPTOR"
)

// RevertWidenRefused is the one detail of REVERT_INVALID for every failed
// proof or token check of rescope_revert (version 21): no proof, a bad or
// replayed proof, a wrong key, no or a wrong token, a select outside the
// ceiling or naming work that is not the caller's.
const RevertWidenRefused = "WIDEN_REFUSED"
