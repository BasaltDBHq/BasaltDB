package ledger

import "github.com/basaltdbhq/basaltdb/internal/core/action"

// The types the services' ports and the inbound adapters use live in
// core/action; these aliases keep the names the ledger's callers know.

type (
	Approval           = action.Approval
	ApprovalListParams = action.ApprovalListParams
	ChangeListParams   = action.ChangeListParams
	Change             = action.Change
	RowChange          = action.RowChange
	BasedOn            = action.BasedOn
	Revert             = action.Revert
	RevertProgress     = action.RevertProgress
	RevertListParams   = action.RevertListParams
	RevertLine         = action.RevertLine
	RevertLineParams   = action.RevertLineParams
	RunListParams      = action.RunListParams
)
