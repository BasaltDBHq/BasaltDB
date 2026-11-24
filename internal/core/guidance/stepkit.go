package guidance

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// AgentStep is an AGENT step of action with text.
func AgentStep(action, text string) toolresult.NextStep {
	return toolresult.NextStep{Actor: toolresult.ActorAgent, Action: action, Text: text}
}

// PersonStep is a PERSON step of action with text.
func PersonStep(action, text string) toolresult.NextStep {
	return toolresult.NextStep{Actor: toolresult.ActorPerson, Action: action, Text: text}
}

// CallTool is an AGENT step: call tool with args.
func CallTool(tool string, args map[string]any, text string) toolresult.NextStep {
	return toolresult.NextStep{Actor: toolresult.ActorAgent, Action: toolresult.ActionCallTool, Text: text, Tool: tool, Arguments: args}
}

// OpenLink is a PERSON step: open url.
func OpenLink(url, text string) toolresult.NextStep {
	return toolresult.NextStep{Actor: toolresult.ActorPerson, Action: toolresult.ActionOpenLink, Text: text, URL: url}
}

// Sentence starts s with a capital letter.
func Sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
