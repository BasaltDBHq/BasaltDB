package action

// The statuses of the ledger's approvals and reverts, as the database keeps
// them.
const (
	ApprovalPending  = "PENDING"
	ApprovalApproved = "APPROVED"
	ApprovalApplied  = "APPLIED"
	ApprovalExpired  = "EXPIRED"

	RevertPending  = "PENDING"
	RevertApplying = "APPLYING"
	RevertApplied  = "APPLIED"
	RevertRejected = "REJECTED"
	RevertExpired  = "EXPIRED"
)
