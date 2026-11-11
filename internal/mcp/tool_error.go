package mcp

// ToolError is a tool failure with a stable code from CONTRACT.md, returned
// in the tools/call result with isError set. Reason refines some codes
// (STATEMENT_REFUSED, QUERY_TIMEOUT); SQLState is set when Postgres raised
// the error; Approval is set on APPROVAL_REQUIRED (M2).
type ToolError struct {
	Code     string          `json:"code"`
	Message  string          `json:"message"`
	Reason   string          `json:"reason,omitempty"`
	SQLState string          `json:"sqlState,omitempty"`
	Approval *ApprovalNotice `json:"approval,omitempty"`
}

// ApprovalNotice is the held write an APPROVAL_REQUIRED error carries: the
// command to give the person (it opens the approval page), the link itself
// for clients that render it, and when it expires.
type ApprovalNotice struct {
	ApprovalID     string `json:"approvalId"`
	ExpiresAt      string `json:"expiresAt"`
	Rows           int    `json:"rows"`
	ApprovalURL    string `json:"approvalUrl"`
	ApproveCommand string `json:"approveCommand"`
}

func (e *ToolError) Error() string {
	return e.Message
}
