package mcp

import "strings"

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
	PersonMessage string `json:"personMessage,omitempty"`
	// Links are the URLs of PersonMessage with labels, in order; set exactly
	// when PersonMessage holds a URL (CONTRACT.md, Showing links).
	Links     []Link     `json:"links,omitempty"`
	NextSteps []NextStep `json:"nextSteps,omitempty"`
	// ErrorID is set on UNAVAILABLE and INTERNAL: a UUIDv7 the engine logs
	// with the error, for the person to find the log line.
	ErrorID string `json:"errorId,omitempty"`
	// DocsURL is the code's section on the public docs, set by the server
	// when it writes the error (DocsURL).
	DocsURL string `json:"docsUrl,omitempty"`
}

// docsErrorsPage is the public page that explains every error code, with one
// anchor per code (CONTRACT.md, Error codes).
const docsErrorsPage = "https://docs.basaltvault.app/reference/errors/"

// DocsURL is the link to code's section on the docs site: the page plus the
// lowercase code with underscores as hyphens (UNKNOWN_TOKEN is #unknown-token).
func DocsURL(code string) string {
	return docsErrorsPage + "#" + strings.ToLower(strings.ReplaceAll(code, "_", "-"))
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

// Link is one URL of a personMessage with a label, so a client that renders
// Markdown can show [label](url) (api/mcp/links/link.schema.json).
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
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
	// Links equals the body's links: the URLs of PersonMessage.
	Links []Link `json:"links,omitempty"`
}

func (e *ToolError) Error() string {
	return e.Message
}

// Warning is a successful result's warning (api/mcp/errors/warning.schema.json):
// the call worked, but something needs attention. A result carries them in
// warnings, absent when there are none.
type Warning struct {
	Code          string     `json:"code"`
	Message       string     `json:"message"`
	Table         string     `json:"table,omitempty"`
	PersonMessage string     `json:"personMessage,omitempty"`
	NextSteps     []NextStep `json:"nextSteps"`
}

// Codes of Warning.
const (
	WarningRLSHidesRows          = "RLS_HIDES_ROWS"
	WarningGuardUpgradeAvailable = "GUARD_UPGRADE_AVAILABLE"
)
