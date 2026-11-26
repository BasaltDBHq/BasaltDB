package guidance

import "github.com/basaltdbhq/basaltdb/internal/core/toolresult"

// panicStop is the one step of a tool call that panicked: the catalog's
// INTERNAL entry (api/mcp/errors/next-steps.json) is a single AGENT STOP.
const panicStop = "Stop. Do not retry this call: the engine failed inside it."

// PanicError is the INTERNAL error a tool call that panicked answers with
// (CONTRACT.md, Crash reports): the catalog's INTERNAL steps and, as the
// catalog requires, a person's message, with errorID, the id the engine
// logged the panic under. It names the saved crash report, or says none
// could be saved when reportID is "". It runs while the server recovers the
// panic, so it never fails: its texts are constants the tests hold to the
// step and message limits.
func PanicError(errorID, reportID string) *toolresult.ToolError {
	steps, _ := NewSteps().Stop(panicStop).Build() // a constant text within the limit
	person := "The basalt engine hit an internal error inside this call and could not save a crash report."
	if reportID != "" {
		person = "The basalt engine hit an internal error and saved a crash report. " +
			"Its id is " + reportID + ". The status tool names the report's file and the link to file it on GitHub."
	}
	return &toolresult.ToolError{Code: CodeInternal, Message: "internal engine error", NextSteps: steps, PersonMessage: person, ErrorID: errorID}
}
