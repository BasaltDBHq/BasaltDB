package guardmodel

// The paths rescope_revert records in REVERT_RESCOPED (CONTRACT.md,
// basalt_meta, Version 21).
const (
	RescopeViaOwnWork    = "OWN_WORK"
	RescopeViaProof      = "PROOF"
	RescopeViaScopeToken = "SCOPE_TOKEN"
)

// The paths reject_revert records in REVERT_REJECTED (CONTRACT.md,
// basalt_meta, Version 23): no token, so Postgres cannot tell the person on
// the link from the agent holding it; or the scope token of a widened
// revert, which only the engine holds for the person's rotated link.
const (
	RejectViaLinkOrAgent = "LINK_OR_AGENT"
	RejectViaScopeToken  = "SCOPE_TOKEN"
)

// MaxRejectNote is the longest note the person may leave with a reject, in
// characters (reverts.reject_note).
const MaxRejectNote = 500
