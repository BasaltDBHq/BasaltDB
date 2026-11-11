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

// ApprovalNotice is the held write an APPROVAL_REQUIRED error carries
// (CONTRACT.md, Handing a held action to the person): what is held, the
// approval link (short when the engine serves the pages), the equivalent
// command, one line for the person, and when it expires.
type ApprovalNotice struct {
	ApprovalID     string `json:"approvalId"`
	ExpiresAt      string `json:"expiresAt"`
	Rows           int    `json:"rows"`
	Headline       string `json:"headline"`
	ApprovalURL    string `json:"approvalUrl"`
	ApproveCommand string `json:"approveCommand"`
	PersonMessage  string `json:"personMessage"`
}

func (e *ToolError) Error() string {
	return e.Message
}
