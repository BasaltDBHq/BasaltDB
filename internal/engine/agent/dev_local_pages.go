package agent

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// problemDevLocalPages is the status problem of an agent-operated engine
// on development pages (CONTRACT.md, Page origins).
const problemDevLocalPages = "DEV_LOCAL_PAGES"

// personMessageKey is the JSON key of every personMessage in a result.
const personMessageKey = "personMessage"

// devLocalMessage puts the DEV_LOCAL_PAGES warning in front of pm, once;
// an empty pm stays empty.
func devLocalMessage(pm string) string {
	if pm == "" || strings.HasPrefix(pm, config.DevLocalPagesWarning) {
		return pm
	}
	return config.DevLocalPagesWarning + "\n\n" + pm
}

// devLocalError is te with the warning on its personMessage and its held
// approval's, on a copy: te may be shared.
func devLocalError(te *mcp.ToolError) *mcp.ToolError {
	out := *te
	out.PersonMessage = devLocalMessage(out.PersonMessage)
	if out.Approval != nil {
		a := *out.Approval
		a.PersonMessage = devLocalMessage(a.PersonMessage)
		out.Approval = &a
	}
	return &out
}

// devLocalResult is the result v with the warning on every personMessage
// it holds, at any depth (results, warnings, list items, status problems).
// It goes through JSON so no result type is missed; numbers keep their text.
func devLocalResult(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	warnPersonMessages(tree)
	return tree, nil
}

func warnPersonMessages(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok && k == personMessageKey {
				t[k] = devLocalMessage(s)
				continue
			}
			warnPersonMessages(x)
		}
	case []any:
		for _, x := range t {
			warnPersonMessages(x)
		}
	}
}

// devLocalPagesSteps: move the engine to the portal's pages with a passkey
// for them, through basalt init's link.
func devLocalPagesSteps(b *Steps, cmds Commands) string {
	b.AgentRunCommand(cmds.Init(), "When the person wants the portal's pages, run this and show them the link it prints, where they register a passkey there.")
	return "This engine uses development pages on the agent's machine instead of the portal. To move to the portal, tell the agent: it gives you a link."
}
