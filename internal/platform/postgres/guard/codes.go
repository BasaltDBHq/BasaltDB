package guard

// The guard's error codes and refusal details: what the Postgres guard
// raises (SQLSTATE class BS, its MESSAGE and its DETAIL). Only the Postgres
// adapters read them; they map each to the store-neutral codes and typed
// reasons of internal/core/action, which the domains read.

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
	ScopeShape = "SHAPE"
	// ScopeName is a tables entry that is not one schema.table name; the
	// hint names the first such entry (version 9).
	ScopeName          = "NAME"
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

// The typed details of apply_revert's REVERT_INVALID (version 11): the
// detail is the code and the hint the sentence. Any other detail of
// REVERT_INVALID there is a signature the guard did not accept.
const (
	// RevertAlreadyApplied is a revert already applied.
	RevertAlreadyApplied = "ALREADY_APPLIED"
	// RevertAlreadySigned is a batched revert already signed.
	RevertAlreadySigned = "ALREADY_SIGNED"
	// RevertPasskeyRevoked is a signature by a revoked passkey.
	RevertPasskeyRevoked = "PASSKEY_REVOKED"
	// RevertRowsChanged is a revert whose rows changed since the preview.
	RevertRowsChanged = "ROWS_CHANGED"
)

// NothingReadsOnly is the detail of NOTHING_TO_REVERT for a scope that
// changed no row a revert could restore (version 11); the hint names the
// scope. Every other NOTHING_TO_REVERT keeps a sentence as its detail.
const NothingReadsOnly = "READS_ONLY"

// RevealRefused is the one detail of APPROVAL_INVALID and REVERT_INVALID for
// every failed reveal proof, key, nonce or ticket check (CONTRACT.md, Rows
// hidden from the agent; version 29).
const RevealRefused = "REVEAL_REFUSED"

// RevealRowsChanged is the detail of APPROVAL_INVALID when a re-run preview's
// lines no longer match the held approval's (reveal_approval_rows): the
// approval can no longer apply.
const RevealRowsChanged = "ROWS_CHANGED"

// Details of the guard's plugin approval refusals: NOT_ALLOWED (BS007) with
// DetailUnknownAgent or DetailTooManyPending from open_plugin_approval,
// APPROVAL_INVALID (BS005) with DetailApprovalNotFound,
// DetailApprovalCancelled or DetailAlreadyApproved from
// submit_plugin_approval. The plugin ledger and the store map them to the
// plugin's typed answers (pluginmodel.StoreError, ApprovalRefusalError).
const (
	DetailUnknownAgent      = "UNKNOWN_AGENT"
	DetailTooManyPending    = "TOO_MANY_PENDING"
	DetailApprovalNotFound  = "NOT_FOUND"
	DetailApprovalCancelled = "CANCELLED"
	DetailAlreadyApproved   = "ALREADY_APPROVED"
)

// DetailHoldTooLarge is the detail of the guard's refusal of preview lines
// over guardmodel.MaxHeldLinesBytes (BS007 NOT_ALLOWED).
const DetailHoldTooLarge = "HOLD_TOO_LARGE"

// SETUP_REFUSED reasons: the DETAIL record_setup raises with BS010.
const (
	SetupUsed         = "USED"
	SetupSuperseded   = "SUPERSEDED"
	SetupExpired      = "EXPIRED"
	SetupIDInFuture   = "SETUP_ID_IN_FUTURE"
	SetupExpiryTooFar = "EXPIRY_TOO_FAR"
)
