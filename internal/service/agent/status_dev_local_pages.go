package agent

import "github.com/basaltdbhq/basaltdb/internal/core/guidance"

// problemDevLocalPages is the status problem of an agent-operated engine
// on development pages (CONTRACT.md, Page origins).
const problemDevLocalPages = "DEV_LOCAL_PAGES"

// devLocalPagesSteps: move the engine to the portal's pages with a passkey
// for them, through basalt init's link.
func devLocalPagesSteps(b *guidance.Steps, cmds Commands) string {
	b.AskPerson("Tell the person this engine uses development pages, and ask whether to move to the portal's pages.")
	b.AgentRunCommand(cmds.Init(), "On the person's yes, run this and show them the link it prints, where they register a passkey there.")
	return "This engine uses development pages on the agent's machine instead of the portal. To move to the portal, tell the agent: it gives you a link."
}
