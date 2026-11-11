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
	// PersonMessage and NextSteps say what to tell the person and what to
	// do next (CONTRACT.md, Next steps).
	PersonMessage string     `json:"personMessage,omitempty"`
	NextSteps     []NextStep `json:"nextSteps,omitempty"`
	// ErrorID is set on UNAVAILABLE and INTERNAL: a UUIDv7 the engine logs
	// with the error, for the person to find the log line.
	ErrorID string `json:"errorId,omitempty"`
}

// Actors and actions of a next step (api/mcp/errors/next-step.schema.json).
const (
	ActorAgent  = "AGENT"
	ActorPerson = "PERSON"

	ActionCallTool            = "CALL_TOOL"
	ActionReviseCall          = "REVISE_CALL"
	ActionRetrySmallerBatches = "RETRY_SMALLER_BATCHES"
	ActionAskPerson           = "ASK_PERSON"
	ActionEndTurn             = "END_TURN"
	ActionStop                = "STOP"
	ActionOpenLink            = "OPEN_LINK"
	ActionRunCommand          = "RUN_COMMAND"
	ActionTellAgent           = "TELL_AGENT"
)

// NextStep is one step of nextSteps in an error body or a result: who does
// it, what, and everything needed to do it (CONTRACT.md, Next steps).
type NextStep struct {
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	Text       string         `json:"text"`
	Tool       string         `json:"tool,omitempty"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	RepeatCall bool           `json:"repeatCall,omitempty"`
	Command    string         `json:"command,omitempty"`
	URL        string         `json:"url,omitempty"`
	// MaxRows is RETRY_SMALLER_BATCHES' row limit; WaitSeconds is how long
	// a CALL_TOOL step waits before the call.
	MaxRows     int `json:"maxRows,omitempty"`
	WaitSeconds int `json:"waitSeconds,omitempty"`
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
