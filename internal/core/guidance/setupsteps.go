package guidance

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// ApprovalExpiredSteps are the steps of an approval that expired before it was approved.
func ApprovalExpiredSteps(b *Steps) {
	b.AskPerson("Tell the person the approval expired and the write stays blocked; ask whether to send it again.")
	b.ReviseCall(ToolWrite, nil, "On yes, send the write again without approvalId, so it is held anew.")
}

// DatabaseUnreachableMessage is the person's message when the database
// cannot be reached, in an error and in status.
const DatabaseUnreachableMessage = "The agent cannot reach the database. Check that Postgres is running and reachable from the machine the engine runs on."

// TooManyConnectionsAsk is the ASK_PERSON step when the agent role is at its
// connection limit, in an error and in status.
const TooManyConnectionsAsk = "Tell the person the agent has used all the database connections BasaltDB allows it, and ask them to stop any second engine for this agent."

// TooManyConnectionsMessage is the person's message when the agent role is at
// its connection limit, in an error and in status (CONTRACT.md, Error codes).
func TooManyConnectionsMessage(cmds Commands) string {
	return fmt.Sprintf("The agent %s has used all %d database connections BasaltDB allows it. "+
		"Another engine for the same agent may be running, or a stopped engine left sessions open. "+
		"Stop any second engine; stale sessions close on their own within a few minutes.",
		cmds.AgentName(), setupcode.AgentConnectionLimit)
}

// fixes are what the person is told for the machine problems of the guard
// and the credential, shared by the UNAVAILABLE errors and the status
// problems of the same name. basalt init fixes each: its link opens the
// setup page, or the connect page on an agent-operated engine, for that job.
var fixes = map[string]string{
	ReasonCredentialRejected: "The database refuses the agent's credential (its password changed or was never right), so the agent needs a new one.",
	ReasonGuardMissing:       "BasaltDB's guard is not installed in this database (or was removed), so the agent cannot work.",
	ReasonGuardOutdated:      "BasaltDB's guard in this database is older than this engine needs, so the agent cannot work until it is updated.",
}

// FixSteps: the agent runs basalt init, whose link the person opens to fix
// reason; the person tells the agent when it is done and the agent stops
// until then. On an agent-operated engine the agent follows what init
// prints instead (RI-17 for CREDENTIAL_REJECTED).
func FixSteps(b *Steps, cmds Commands, reason string) string {
	problem, ok := fixes[reason]
	if !ok {
		b.Fail(fmt.Errorf("no fix for %s", reason))
		return ""
	}
	if cmds.AgentOperated() {
		return RemoteSetupSteps(b, cmds, problem)
	}
	if cmds.EngineRemoved() {
		// The setup page removed BasaltDB and the engine's last agent: its
		// role is gone, so every call fails, and the engine removes itself
		// from this computer (CONTRACT.md, The local setup page, Removing
		// the engine service).
		return RemovedSteps(b, cmds)
	}
	if reason == ReasonGuardOutdated && cmds.UpdateLinkURL() != "" {
		b.OpenLink(cmds.UpdateLinkURL(), "Show the person this link: its page updates the guard once they type the admin connection string there.")
		b.TellAgent("Tell the agent when it is done.")
		b.Stop("Do not retry until the person says it is fixed.")
		return problem + " Open the link the agent gives you, follow the page, then tell the agent."
	}
	b.AgentRunCommand(cmds.Init(), initStepText)
	b.TellAgent("Tell the agent when it is done.")
	b.Stop("Do not retry until the person says it is fixed.")
	return problem + " " + initPersonText
}

// GuardBelowFloorSteps are the fix steps of a guard below the build's
// update floor, an install from 0.0.1 (GUARD_OUTDATED with
// guardmodel.Status.BelowFloor): never the setup page's UPDATE link, which
// cannot update it. The person removes the install as doc says, and the
// link basalt init prints sets BasaltDB up again.
func GuardBelowFloorSteps(b *Steps, cmds Commands, doc string) (string, []toolresult.Link) {
	m := NewMessage().
		Text("BasaltDB's guard in this database is from an older BasaltDB release that this engine cannot update, so the agent cannot work. Remove the old install first, as this page says:").
		Link("Remove an older install", doc)
	if cmds.AgentOperated() {
		b.AgentRunCommand(cmds.Init(), "Run this once the person has removed the old install, then show them the link it prints and follow its steps.")
		return m.Text("Then the agent gives you a link to set up again.").Build()
	}
	b.AgentRunCommand(cmds.Init(), "Run this once and show the person the link it prints: they remove the old install first, then set up again.")
	b.TellAgent("Tell the agent when it is done.")
	b.Stop("Do not retry until the person says it is set up again.")
	return m.Text("Then open the link the agent gives you to set up again, and tell the agent when it is done.").Build()
}

// RemovedSteps are the steps after the person removed BasaltDB (the
// problem REMOVED, and the failing calls of an engine the setup page
// removed): the agent removes its own MCP entry for basalt and stops. It
// returns the personMessage.
func RemovedSteps(b *Steps, cmds Commands) string {
	b.Stop(fmt.Sprintf("BasaltDB is removed: remove this MCP server (basalt mcp --agent %s) from your MCP config, show the person the message, and stop.", cmds.AgentName()))
	return RemovedPersonText
}

// RemovedPersonText is what the person reads after a removal.
const RemovedPersonText = "BasaltDB is removed. Your agent drops its connection to it now. If you did not remove BasaltDB, or want it back, ask the agent to run basalt init."

// initStepText is the text of the agent's basalt init step: it prints the
// one link the person opens (CONTRACT.md, basalt init).
const initStepText = "Run this once and show the person the link it prints; they fix it on that page."

// PasskeyInitText is the text of the agent's basalt init step for a passkey
// the database does not accept.
const PasskeyInitText = "Run this once and show the person the link it prints, where they register the passkey they use."

// AskAgentForRegisterLinkText is a page's step for a passkey the database does not
// accept: the page cannot run basalt init, so the person asks the agent.
const AskAgentForRegisterLinkText = "Ask the agent for a link to register the passkey you use."

// initPersonText tells the person what follows the agent's basalt init.
const initPersonText = "The agent gives you a link: open it, follow the page, then tell the agent."

// RemoteSetupSteps: on an agent-operated engine, the agent runs basalt init
// now; what it prints (the connect link, its personMessage and nextSteps)
// replaces the rest of these steps (RI-2). The person's message names no
// command on the agent's machine.
func RemoteSetupSteps(b *Steps, cmds Commands, problem string) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the link it prints and follow its steps.")
	return problem + " " + initPersonText
}

// EngineUnreachableSteps: the person starts the engine; on an agent-operated
// engine the agent starts it, once, then repeats tool (status when tool is
// empty or status itself).
func EngineUnreachableSteps(b *Steps, cmds Commands, tool string) string {
	if !cmds.AgentOperated() {
		return personFix(b, cmds.EngineStart(), "The agent cannot reach the engine, so it is not running.")
	}
	b.AgentRunCommand(cmds.EngineStart(), "Start the BasaltDB engine on this machine, once; ask the person when it still does not answer.")
	if tool == "" || tool == ToolStatus {
		b.CallTool(ToolStatus, map[string]any{}, "Then call status to check that the engine answers.")
		return ""
	}
	b.RepeatCall(tool, nil, 0, "Then make the same call again, once.")
	return ""
}

func personFix(b *Steps, command, problem string) string {
	b.RunCommand(command, "Run this to fix it.")
	b.TellAgent("Tell the agent when it is done.")
	b.Stop("Do not retry until the person says it is fixed.")
	return fmt.Sprintf("%s Run: %s then tell the agent.", problem, command)
}

// SetupCode is a setup code's alphabet: basalt-setup.1.<base64url>.<check>.
var SetupCode = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// SetupExpiredSteps: the agent runs basalt init again for a new link.
func SetupExpiredSteps(b *Steps, cmds Commands) string {
	b.AgentRunCommand(cmds.Init(), "Run this once, then show the person the new link it prints and follow its steps.")
	b.EndTurn("End your turn: the person opens the new link next.")
	return "The setup link for this agent expired before it was used. " + initPersonText
}

// SetupPendingSteps: the person finishes the pending setup on the connect
// page, checking it shows fingerprint. An INSTALL code blocks the tools
// (blocking), so the agent ends its turn and checks status after; an AGENT
// or UPGRADE code does not.
//
// With a connect link (budget is not 0 and the whole link fits it) the
// person opens it, and the message says the link uses BasaltVault, a
// hosted service (CONTRACT.md, Next steps with the connect link). Without
// one there is no page to hand over: the agent runs basalt init, which
// prints the link. The links are those of the message.
func SetupPendingSteps(b *Steps, cmds Commands, code, fingerprint string, blocking bool, budget int) (string, []toolresult.Link) {
	if !SetupCode.MatchString(code) || fingerprint == "" {
		b.Fail(errors.New("a pending setup needs its code and fingerprint"))
		return "", nil
	}
	url := ConnectLink(code, budget)
	if url != "" {
		b.OpenLink(url, ConnectStepText)
	} else {
		b.AgentRunCommand(cmds.Init(), "Run this once and show the person the link it prints, where they finish the setup.")
	}
	b.TellAgent("Tell the agent when it is done.")
	lead := "A change to this agent's setup is waiting for you."
	if blocking {
		b.EndTurn("End your turn: the person acts next.")
		b.CallTool(ToolStatus, map[string]any{}, "When the person says it is done, check that the agent is ready.")
		lead = "This agent's setup has not run yet."
	}
	if url != "" {
		return ConnectMessage(lead, url, fingerprint)
	}
	return lead + " The agent gives you a link: open it, check that it shows the setup fingerprint " + fingerprint +
		", and follow the page, then tell the agent. Never paste your database password into this chat.", nil
}

// NothingSignableLead says why nothing the agent holds can be approved yet.
const NothingSignableLead = "No passkey is registered for this agent, so nothing it holds for you can be approved yet."

// NoPasskeySteps: the agent runs basalt init, whose link opens the page
// where the person registers a passkey; on an agent-operated engine the
// connect page (RI-6: the person's computer registers a portal passkey when
// none is active).
func NoPasskeySteps(b *Steps, cmds Commands) string {
	const lead = NothingSignableLead
	if cmds.AgentOperated() {
		return RemoteSetupSteps(b, cmds, lead)
	}
	b.AgentRunCommand(cmds.Init(), "Run this once and show the person the link it prints, where they register a passkey: held writes and reverts are signed with one.")
	return lead + " The agent gives you a link to register one."
}
