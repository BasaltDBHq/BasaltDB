package action

// The statuses of the ledger's approvals and reverts, as the database keeps
// them.
const (
	ApprovalPending  = "PENDING"
	ApprovalApproved = "APPROVED"
	ApprovalApplied  = "APPLIED"
	ApprovalExpired  = "EXPIRED"
	// ApprovalWithdrawn is a held write the agent withdrew before the
	// person signed it.
	ApprovalWithdrawn = "WITHDRAWN"

	RevertPending  = "PENDING"
	RevertApplying = "APPLYING"
	RevertApplied  = "APPLIED"
	RevertRejected = "REJECTED"
	RevertExpired  = "EXPIRED"
	// RevertWithdrawn is a revert the agent withdrew before the person
	// signed it.
	RevertWithdrawn = "WITHDRAWN"
)
