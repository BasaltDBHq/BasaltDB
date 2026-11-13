package agent

import (
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// Limits of next-step.schema.json and tool-error.schema.json, in characters.
const (
	// MaxStepTextLength is the most a step's text may hold.
	MaxStepTextLength = 200
	// MaxPersonMessageLength is the most a personMessage may hold.
	MaxPersonMessageLength = 500
	// MaxRetryRows is the most rows RETRY_SMALLER_BATCHES may allow.
	MaxRetryRows = 50
	// MaxWaitSeconds is the longest a CALL_TOOL step may wait.
	MaxWaitSeconds = 60
)

// ErrStepText is a step text or person message that is empty or too long.
var ErrStepText = errors.New("step text out of bounds")

// NextStep is one step of nextSteps (api/mcp/errors/next-step.schema.json).
type NextStep = mcp.NextStep

// Steps builds a nextSteps list, one constructor per action. A step that
// breaks the schema (text over its limit, a missing tool or command) is
// refused when Build is called, so a bad step fails in the engine's tests,
// not in the agent's hands. The first problem is the one reported.
type Steps struct {
	steps []NextStep
	err   error
}

// NewSteps starts an empty list.
func NewSteps() *Steps { return &Steps{} }

// CallTool adds an AGENT step: call tool with arguments.
func (b *Steps) CallTool(tool string, args map[string]any, text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionCallTool, Tool: tool, Arguments: args}, text)
}

// RepeatCall adds an AGENT step: repeat the call that returned the step with
// args merged in (a null value removes an argument), after waitSeconds when
// that is above zero.
func (b *Steps) RepeatCall(tool string, args map[string]any, waitSeconds int, text string) *Steps {
	if waitSeconds < 0 || waitSeconds > MaxWaitSeconds {
		return b.fail(fmt.Errorf("wait of %d seconds is outside 0 to %d", waitSeconds, MaxWaitSeconds))
	}
	return b.add(NextStep{
		Actor: mcp.ActorAgent, Action: mcp.ActionCallTool, Tool: tool, Arguments: args,
		RepeatCall: true, WaitSeconds: waitSeconds,
	}, text)
}

// ReviseCall adds an AGENT step: change the call as text says, then call
// tool; args are what the engine can fill in.
func (b *Steps) ReviseCall(tool string, args map[string]any, text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionReviseCall, Tool: tool, Arguments: args}, text)
}

// RetrySmallerBatches adds an AGENT step: split the write into writes of at
// most maxRows rows.
func (b *Steps) RetrySmallerBatches(maxRows int, text string) *Steps {
	if maxRows < 1 || maxRows > MaxRetryRows {
		return b.fail(fmt.Errorf("maxRows %d is outside 1 to %d", maxRows, MaxRetryRows))
	}
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionRetrySmallerBatches, MaxRows: maxRows}, text)
}

// AskPerson adds an AGENT step: ask the person.
func (b *Steps) AskPerson(text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson}, text)
}

// EndTurn adds an AGENT step: end the turn, the person acts next.
func (b *Steps) EndTurn(text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionEndTurn}, text)
}

// Stop adds an AGENT step: do not retry and do not work around.
func (b *Steps) Stop(text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionStop}, text)
}

// OpenLink adds a PERSON step: open url; command, when not empty, opens the
// same page from a terminal.
func (b *Steps) OpenLink(url, command, text string) *Steps {
	if url == "" {
		return b.fail(errors.New("OPEN_LINK needs a url"))
	}
	return b.add(NextStep{Actor: mcp.ActorPerson, Action: mcp.ActionOpenLink, URL: url, Command: command}, text)
}

// RunCommand adds a PERSON step: run command in a terminal.
func (b *Steps) RunCommand(command, text string) *Steps {
	if command == "" {
		return b.fail(errors.New("RUN_COMMAND needs a command"))
	}
	return b.add(NextStep{Actor: mcp.ActorPerson, Action: mcp.ActionRunCommand, Command: command}, text)
}

// AgentRunCommand adds an AGENT step: run command on the engine's machine.
// Only an agent-operated engine returns one (CONTRACT.md, Next steps), and
// never with a command that needs the admin connection string (CO-9).
func (b *Steps) AgentRunCommand(command, text string) *Steps {
	if command == "" {
		return b.fail(errors.New("RUN_COMMAND needs a command"))
	}
	return b.add(NextStep{Actor: mcp.ActorAgent, Action: mcp.ActionRunCommand, Command: command}, text)
}

// MachineCommand adds a machine step on the engine's machine (a catalog
// OPERATOR step): the agent's on an agent-operated engine, with
// agentText, else the person's, with personText.
func (b *Steps) MachineCommand(cmds Commands, command, personText, agentText string) *Steps {
	if cmds.AgentOperated() {
		return b.AgentRunCommand(command, agentText)
	}
	return b.RunCommand(command, personText)
}

// TellAgent adds a PERSON step: the person tells the agent to go on.
func (b *Steps) TellAgent(text string) *Steps {
	return b.add(NextStep{Actor: mcp.ActorPerson, Action: mcp.ActionTellAgent}, text)
}

// Build returns the steps, first step first, or the first problem found.
func (b *Steps) Build() ([]NextStep, error) {
	if b.err != nil {
		return nil, b.err
	}
	if len(b.steps) == 0 {
		return nil, errors.New("nextSteps needs at least one step")
	}
	return b.steps, nil
}

func (b *Steps) add(s NextStep, text string) *Steps {
	if b.err != nil {
		return b
	}
	if s.Tool == "" && (s.Action == mcp.ActionCallTool || s.Action == mcp.ActionReviseCall) {
		return b.fail(fmt.Errorf("%s needs a tool", s.Action))
	}
	if err := checkLength("text", text, MaxStepTextLength, true); err != nil {
		return b.fail(fmt.Errorf("%s: %w", s.Action, err))
	}
	s.Text = text
	b.steps = append(b.steps, s)
	return b
}

func (b *Steps) fail(err error) *Steps {
	if b.err == nil {
		b.err = err
	}
	return b
}

// urlLines are the lines of a personMessage that hold a URL, with their line
// break: the limit does not count them (CONTRACT.md, Links in personMessage).
var urlLines = regexp.MustCompile(`(?m)^https?://\S+\n?`)

// CheckPersonMessage refuses a personMessage over its limit, not counting its
// URL lines. It may be empty: not every error needs the person.
func CheckPersonMessage(message string) error {
	return checkLength("personMessage", urlLines.ReplaceAllString(message, ""), MaxPersonMessageLength, false)
}

func checkLength(field, text string, limit int, required bool) error {
	n := utf8.RuneCountInString(text)
	switch {
	case required && n == 0:
		return fmt.Errorf("%w: %s is empty", ErrStepText, field)
	case n > limit:
		return fmt.Errorf("%w: %s is %d characters, the limit is %d", ErrStepText, field, n, limit)
	}
	return nil
}
