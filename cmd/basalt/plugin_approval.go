package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Plugin approval (CONTRACT.md, Plugins, Plugin approval and Plugin
// approval commands), same-user mode only. When an agent runs basalt
// plugin add or enable, on an agent-operated engine, for an entry that
// already requires approval, or with --approve-with-passkey, the command
// checks the copy, writes the entry with "approval": "REQUIRED", opens one
// plugin approval per database through the guard with the listed agents'
// credentials, and hands over a link. Nothing it does is consent: the
// person signs on the page, Postgres verifies the signature, and the
// engine serves the entry only on a matching approval.

// Reasons of PLUGIN_REFUSED the approval flow adds.
const (
	reasonTooManyPending      = "TOO_MANY_PENDING"
	reasonGuardOutdated       = "GUARD_OUTDATED"
	reasonDatabaseUnreachable = "DATABASE_UNREACHABLE"
)

// databaseTimeout bounds each database's checks and its open: the 15
// seconds of the contract.
const databaseTimeout = 15 * time.Second

// flagApproveWithPasskey chooses the approval flow for a person.
const flagApproveWithPasskey = "approve-with-passkey"

// approvalFlow reports whether add or enable for entry prev (nil for a new
// entry) takes the approval flow: an agent marker is set, the engine is
// agent-operated, the entry already requires approval, or the person asked.
// In service mode it never does: there the commands are as in Consent.
func (e *pluginEnv) approvalFlow(cfg config.Config, prev *config.Plugin, asked bool) bool {
	if cfg.Service() {
		return false
	}
	return asked || e.c.agentMarker() != "" || cfg.AgentOperated() || (prev != nil && prev.Approval == config.PluginApprovalRequired)
}

// errApprovalInServiceMode: the flag and basalt plugin approve wait for the
// service mode contract.
func errApprovalInServiceMode(what string) error {
	return fmt.Errorf("%w: %s is for an engine in same-user mode; this engine runs as a service, where plugins are added "+
		"with sudo basalt plugin add in a terminal of your own", errUsage, what)
}

// approvalGroup is the listed agents of one database: the database their
// credentials connect to, each agent's name and role, and the connection of
// the first, which opens the approval.
type approvalGroup struct {
	host, database string
	port           uint16
	agents, roles  []string
	conn           *pgx.Conn
	// install is the guard's install id: one per database, whatever the
	// connection string calls its host.
	install uuid.UUID
	// passkeys are the database's registered passkeys, for the link's
	// credentialIds; none means nobody can sign yet.
	passkeys []passkey.Credential
}

func (g *approvalGroup) close(ctx context.Context) {
	if g.conn != nil {
		_ = g.conn.Close(context.WithoutCancel(ctx))
	}
}

// opener is the agent whose credential opens the group's approval.
func (g *approvalGroup) opener() string { return g.agents[0] }

func closeGroups(ctx context.Context, groups []*approvalGroup) {
	for _, g := range groups {
		g.close(ctx)
	}
}

// approvalGroups reads every listed agent's credential, groups the agents
// by the database they connect to, in --agents order, and checks each
// database before anything is written: it answers within 15 seconds and its
// guard has plugin approvals. Agents are grouped first by the connection
// string's host, port and database name, then the groups whose guard has
// the same install id are merged: two spellings of one host are one
// database, so it gets one approval, not two that cancel each other. A
// failure is the refusal the contract names; again is the refused command.
func (e *pluginEnv) approvalGroups(agents []string, again string) ([]*approvalGroup, error) {
	if len(agents) == 0 {
		return nil, errors.New("the entry serves no agent, so there is nothing to approve; name its agents with --agents")
	}
	var groups []*approvalGroup
	byKey := map[string]*approvalGroup{}
	for _, name := range agents {
		a, ok := agentOf(e.cfg, name)
		if !ok {
			closeGroups(e.c.ctx, groups)
			return nil, errAgentNotInConfig(name, e.configPath)
		}
		dsn, err := e.ec.credential(a.Store.CredentialFile)
		if err != nil {
			closeGroups(e.c.ctx, groups)
			return nil, e.unreachable(name, "its credential file cannot be read", again)
		}
		pc, err := pgx.ParseConfig(dsn)
		if err != nil {
			closeGroups(e.c.ctx, groups)
			return nil, e.unreachable(name, "its credential is not a connection string", again)
		}
		key := fmt.Sprintf("%s\x00%d\x00%s", pc.Host, pc.Port, pc.Database)
		g, ok := byKey[key]
		if !ok {
			g = &approvalGroup{host: pc.Host, port: pc.Port, database: pc.Database}
			if err := e.checkDatabase(g, name, dsn, again); err != nil {
				closeGroups(e.c.ctx, groups)
				return nil, err
			}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.agents = append(g.agents, name)
		g.roles = append(g.roles, pc.User)
	}
	return e.mergeByInstall(groups), nil
}

// mergeByInstall merges the groups whose guard has the same install id
// into the first of them, keeping --agents order of the first agents.
func (e *pluginEnv) mergeByInstall(groups []*approvalGroup) []*approvalGroup {
	out := make([]*approvalGroup, 0, len(groups))
	first := map[uuid.UUID]*approvalGroup{}
	for _, g := range groups {
		if into, ok := first[g.install]; ok {
			into.agents = append(into.agents, g.agents...)
			into.roles = append(into.roles, g.roles...)
			g.close(e.c.ctx)
			continue
		}
		first[g.install] = g
		out = append(out, g)
	}
	return out
}

// checkDatabase connects as agent, the first of g, within 15 seconds, and
// reads the guard's version and the database's passkeys.
func (e *pluginEnv) checkDatabase(g *approvalGroup, agentName, dsn, again string) error {
	ctx, cancel := context.WithTimeout(e.c.ctx, databaseTimeout)
	defer cancel()
	conn, err := connect(ctx, dsn)
	if err != nil {
		return e.unreachable(agentName, "its database does not answer ("+connectWhy(err)+")", again)
	}
	g.conn = conn
	st, err := guard.AgentStatus(ctx, conn, guard.Migrations())
	if err != nil {
		g.close(e.c.ctx)
		return e.unreachable(agentName, "its guard cannot be read ("+pgDetail(err)+")", again)
	}
	if !holdsPluginApprovals(st) {
		g.close(e.c.ctx)
		return e.guardOutdated(agentName)
	}
	if g.install, err = guard.InstallID(ctx, conn); err != nil {
		g.close(e.c.ctx)
		return e.unreachable(agentName, "its guard cannot be read ("+pgDetail(err)+")", again)
	}
	keys, err := ledger.Passkeys(ctx, conn)
	if err != nil {
		g.close(e.c.ctx)
		return e.unreachable(agentName, "its passkeys cannot be read ("+pgDetail(err)+")", again)
	}
	g.passkeys = keys
	return nil
}

// connectWhy is a connection failure without the connection string: the
// Postgres error's message, or that it timed out.
func connectWhy(err error) string {
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe):
		return pe.Message
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer within 15 seconds"
	}
	return "the connection failed"
}

// holdsPluginApprovals reports whether a guard has plugin approvals.
func holdsPluginApprovals(st guard.Status) bool {
	return st.Installed >= guard.PluginApprovalsVersion &&
		!slices.Contains(st.MissingBreaking, guard.PluginApprovalsVersion) &&
		!slices.Contains(st.MissingNonBreaking, guard.PluginApprovalsVersion)
}

// commandsFor are the commands of agent on this engine.
func (e *pluginEnv) commandsFor(agentName string) (agent.Commands, error) {
	cmds, err := agent.NewCommands(agentName, e.configPath, e.c.goos)
	if err != nil {
		return agent.Commands{}, err
	}
	if !e.cfg.Service() {
		cmds = cmds.Foreground()
	}
	return cmds.OperatedBy(e.cfg.OperatedBy), nil
}

// unreachable is PLUGIN_REFUSED DATABASE_UNREACHABLE before anything was
// written: the step runs the refused command again.
func (e *pluginEnv) unreachable(agentName, why, again string) error {
	cmds, err := e.commandsFor(agentName)
	if err != nil {
		return err
	}
	steps, err := agent.NewSteps().
		AskPerson("Ask the person to check that the agent's database is up and reachable from this machine.").
		MachineCommand(cmds, again, "Run the command again once the database answers.", "Run the command again once the person says the database answers.").
		Build()
	if err != nil {
		return err
	}
	return &pluginRefusedError{
		reason:  reasonDatabaseUnreachable,
		message: fmt.Sprintf("the plugin approval cannot be opened: agent %s: %s. Nothing was written", agentName, why),
		person:  fmt.Sprintf("Basalt could not reach the database of agent %s, so the plugin was not added. Check that the database is up.", agentName),
		steps:   steps,
	}
}

// guardOutdated is PLUGIN_REFUSED GUARD_OUTDATED: the agent's guard has no
// plugin approvals. On an agent-operated engine the agent makes an UPGRADE
// setup code; else the person upgrades the guard.
func (e *pluginEnv) guardOutdated(agentName string) error {
	cmds, err := e.commandsFor(agentName)
	if err != nil {
		return err
	}
	r := &pluginRefusedError{
		reason: reasonGuardOutdated,
		message: fmt.Sprintf("the plugin approval cannot be opened: the guard in the database of agent %s is older than schema version %d, "+
			"which holds plugin approvals. Nothing was written", agentName, guard.PluginApprovalsVersion),
	}
	b := agent.NewSteps()
	b.AgentRunCommand(cmds.Init(), guardUpdateText)
	if !cmds.AgentOperated() {
		b.TellAgent("Tell the agent once the guard is updated.").
			Stop("Stop until the person says the guard is updated, then run the refused command again.")
	}
	r.person = "Basalt's guard in the agent's database is older than plugin approvals need. The agent gives you a link to update it: " +
		"open it, follow the page, then tell the agent."
	steps, err := b.Build()
	if err != nil {
		return err
	}
	r.steps = steps
	return r
}

// guardUpdateText is the text of the agent's basalt init step for a guard
// older than plugin approvals need.
const guardUpdateText = "Run this once and show the person the link it prints, where they update the guard in the agent's database."

// approvalResult is basalt plugin add and enable --json when the command
// opened plugin approvals (api/plugin/approval/result.schema.json).
type approvalResult struct {
	Name          string         `json:"name"`
	Instance      string         `json:"instance"`
	Approvals     []approvalItem `json:"approvals"`
	PersonMessage string         `json:"personMessage"`
	Links         []mcp.Link     `json:"links,omitempty"`
	NextSteps     []mcp.NextStep `json:"nextSteps"`
}

type approvalItem struct {
	Database    approvalDatabase   `json:"database"`
	Agents      []string           `json:"agents"`
	ApprovalID  string             `json:"approvalId,omitempty"`
	ExpiresAt   string             `json:"expiresAt,omitempty"`
	URL         string             `json:"url,omitempty"`
	RequestFile *links.RequestFile `json:"requestFile,omitempty"`
	Refused     *approvalRefused   `json:"refused,omitempty"`
}

type approvalDatabase struct {
	Host string `json:"host"`
	Name string `json:"name"`
}

type approvalRefused struct {
	Code    string `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// openedApproval is one database's opened approval with its link.
type openedApproval struct {
	group   *approvalGroup
	opened  guard.PluginApproval
	binding approval.PluginBinding
	url     string
	file    *links.RequestFile
	refused *approvalRefused
}

// openApprovals opens one approval per group for entry p, the copy v and
// the agents' roles, and builds each link. A database that refuses now is
// recorded in its item; the entry stays written.
func (e *pluginEnv) openApprovals(groups []*approvalGroup, p config.Plugin, v plugin.Verified) []openedApproval {
	out := make([]openedApproval, 0, len(groups))
	for _, g := range groups {
		o := openedApproval{group: g}
		ctx, cancel := context.WithTimeout(e.c.ctx, databaseTimeout)
		opened, err := guard.OpenPluginApproval(ctx, g.conn, engine.PluginApprovalDetail(p.Key(), v, g.roles), p.ApprovalSettings())
		cancel()
		if err != nil {
			o.refused = openRefusal(err)
			out = append(out, o)
			continue
		}
		o.opened = opened
		b, err := approval.ParsePluginBinding(opened.BindingText)
		if err == nil {
			o.binding = b
			o.url, o.file, err = e.approvalLink(g, opened)
		}
		if err != nil {
			o.refused = &approvalRefused{Code: codePluginRefused, Reason: reasonDatabaseUnreachable, Message: "the approval was opened but no link could be made: " + err.Error()}
		}
		out = append(out, o)
	}
	return out
}

// openRefusal maps a failed open_plugin_approval to its reason (CONTRACT.md,
// The flow, step 3).
func openRefusal(err error) *approvalRefused {
	var pe *pgconn.PgError
	r := &approvalRefused{Code: codePluginRefused, Reason: reasonDatabaseUnreachable, Message: pgDetail(err)}
	switch {
	case errors.As(err, &pe) && pe.Code == "BS007" && pe.Detail == guard.DetailTooManyPending:
		r.Reason = reasonTooManyPending
		r.Message = "8 plugin approvals already wait in this database"
	case errors.As(err, &pe) && pe.Code == "BS007" && pe.Detail == guard.DetailUnknownAgent:
		r.Reason = reasonUnknownAgent
		r.Message = "a listed agent is not an agent role of this database"
	case errors.As(err, &pe) && pe.Code == "42883":
		r.Reason = reasonGuardOutdated
		r.Message = fmt.Sprintf("the guard is older than schema version %d", guard.PluginApprovalsVersion)
	case !errors.As(err, &pe):
		r.Message = "the database does not answer: " + connectWhy(err)
	}
	return r
}

// approvalLink is the link to the plugin approval page: a short link when
// the engine serves the local pages, else the long link, or the hash link
// with its request file when the long one is over the link budget.
func (e *pluginEnv) approvalLink(g *approvalGroup, opened guard.PluginApproval) (string, *links.RequestFile, error) {
	ids := make([]passkey.Bytes, 0, len(g.passkeys))
	for _, k := range g.passkeys {
		ids = append(ids, k.ID)
	}
	base, err := e.cfg.PagesBase()
	if err != nil {
		base = links.DefaultLocal
	}
	long, err := approval.PluginRequest{ApprovalID: opened.ID, Binding: opened.BindingText, Settings: opened.SettingsText, CredentialIDs: ids}.URL(base)
	if err != nil {
		return "", nil, err
	}
	pages := linkPages{base: base, local: localPages(e.c, "", g.opener(), e.configPath)}
	if link := pages.short(e.c, "plugins", opened.ID, opened.BindingText, long); link != long {
		return link, nil, nil
	}
	if len(long) <= e.cfg.LinkBudgetOrDefault() {
		return long, nil, nil
	}
	hash, file, err := links.HashLink(long, links.PluginFile(opened.ID))
	if err != nil {
		return "", nil, err
	}
	return hash, &file, nil
}

// The page's level lines (CONTRACT.md, The plugin approval page, The
// sentences): personMessage carries the same words, so an honest agent
// relays the warning; the page is the protection.
const (
	levelKnown       = "Published by Basalt."
	levelUnknown     = "Nobody vouches for this plugin. Add it only if you trust where it came from."
	levelUnknownHere = "Nobody vouches for this plugin. It runs a stranger's program on the computer Basalt runs on, with the same " +
		"access as Basalt itself, so it could read your database password and the key Basalt uses to hide private values."
)

// pluginLevel is the page's level of a binding, from signer, endpoint and
// isolation, as the page derives it.
func pluginLevel(b approval.PluginBinding) int {
	if b.Signer == guard.PluginSignerKnown {
		return levelPublished
	}
	var endpoint struct {
		Kind string `json:"kind"`
	}
	var isolation struct {
		Files string `json:"files"`
	}
	_ = json.Unmarshal(b.Endpoint, &endpoint)
	if len(b.Isolation) > 0 {
		_ = json.Unmarshal(b.Isolation, &isolation)
	}
	if endpoint.Kind == guard.PluginEndpointRemote || isolation.Files == guard.PluginFilesOSUser {
		return levelFenced
	}
	return levelUnfenced
}

// The page's three levels, from calm to the strong warning.
const (
	levelPublished = 1 + iota
	levelFenced
	levelUnfenced
)

func levelLine(level int) string {
	switch level {
	case levelPublished:
		return levelKnown
	case levelFenced:
		return levelUnknown
	}
	return levelUnknownHere
}

// approvalOutcome builds the result: the person's message with the level
// line of the strongest binding, each link, the earliest expiry, and the
// steps.
func (e *pluginEnv) approvalOutcome(k plugin.EntryKey, version string, items []openedApproval) (approvalResult, error) {
	res := approvalResult{Name: k.Name, Instance: k.Instance}
	var (
		level, opened int
		change        bool
		expires       time.Time
		noPasskey     []*approvalGroup
		refusedText   []string
		requester     string
	)
	steps := agent.NewSteps()
	for _, o := range items {
		item := approvalItem{
			Database: approvalDatabase{Host: o.group.host, Name: o.group.database},
			Agents:   slices.Clone(o.group.agents),
		}
		if o.refused != nil {
			item.Refused = o.refused
			refusedText = append(refusedText, fmt.Sprintf("No approval was opened for database %s.", o.group.database))
			res.Approvals = append(res.Approvals, item)
			continue
		}
		opened++
		item.ApprovalID, item.ExpiresAt, item.URL, item.RequestFile = o.opened.ID.String(), o.opened.ExpiresAt.UTC().Format(time.RFC3339), o.url, o.file
		res.Approvals = append(res.Approvals, item)
		level = max(level, pluginLevel(o.binding))
		change = change || len(o.binding.Change) > 0
		if expires.IsZero() || o.opened.ExpiresAt.Before(expires) {
			expires = o.opened.ExpiresAt
		}
		if requester == "" {
			requester = o.group.opener()
		}
		if len(o.group.passkeys) == 0 {
			noPasskey = append(noPasskey, o.group)
		}
		label := "Approve the plugin " + k.Name
		if len(items) > 1 {
			label += " for database " + labelText(o.group.database)
		}
		res.Links = append(res.Links, mcp.Link{Label: label, URL: o.url})
	}
	cmds, err := e.commandsFor(e.firstAgent(items))
	if err != nil {
		return approvalResult{}, err
	}
	var noPasskeyText, msg []string
	for _, g := range noPasskey {
		noPasskeyText = append(noPasskeyText, fmt.Sprintf("Nobody can approve this yet: no passkey is registered for database %s.", g.database))
		gc, err := e.commandsFor(g.opener())
		if err != nil {
			return approvalResult{}, err
		}
		steps.AgentRunCommand(gc.Init(), "Nobody can approve yet: run this once and show the person the link it prints, where they register a passkey.")
	}
	if opened > 0 {
		lead := fmt.Sprintf("%s asks you to approve the plugin %s %s.", requester, k.Name, visibleText(version))
		if change {
			lead = fmt.Sprintf("%s asks you to approve a change to the plugin %s %s.", requester, k.Name, visibleText(version))
		}
		ask := "Approve it with your passkey:"
		if level == levelUnfenced {
			ask = "Approve it with your passkey only if you know who made it:"
		}
		msg = append(msg, lead, levelLine(level), ask)
		for _, o := range items {
			if o.refused != nil {
				continue
			}
			// A hash link's request file goes by the SEND_REQUEST step.
			msg = append(msg, o.url)
			steps.SendRequest(o.file)
		}
		msg = append(msg, fmt.Sprintf("Expires %s. The plugin starts within seconds of your approval.", expires.UTC().Format(personTime)))
		var ids []uuid.UUID
		for _, o := range items {
			if o.refused == nil {
				steps.OpenLink(o.url, "Open the link, read what the plugin may do and approve it with your passkey.")
				ids = append(ids, o.opened.ID)
			}
		}
		steps.AgentRunCommand(e.waitCommand(k, ids), fmt.Sprintf("Show the person personMessage first. Then, in the same turn, run this: it returns as soon as the plugin runs, or after %d seconds.", defaultRepeatWait))
	}
	// What the refused databases need comes before the agent ends its turn.
	e.refusedSteps(steps, cmds, items, k)
	if opened > 0 {
		// No restart: the running engine starts the plugin once a matching
		// approval is signed (CONTRACT.md, Plugin changes while the engine
		// runs).
		steps.TellAgent("Tell the agent once you approved, or give it the basalt-plugin.1. code the page shows.")
		steps.EndTurn("When that wait ended without the plugin running, end your turn: the person approves next. When they paste a basalt-plugin.1. code, run basalt plugin approve with it, then the wait again.")
	}
	res.PersonMessage = fitPersonMessage(noPasskeyText, msg, refusedText)
	built, err := steps.Build()
	if err != nil {
		return approvalResult{}, err
	}
	res.NextSteps = built
	return res, nil
}

// fitPersonMessage is the person's message within its limit. The entry is
// already written, so it never fails: it drops, in this order, the
// databases that opened none and then the no-passkey lines (their steps
// stay), and always keeps the level line, the links and the expiry.
func fitPersonMessage(noPasskey, core, refused []string) string {
	for _, parts := range [][][]string{{noPasskey, core, refused}, {noPasskey, core}, {core}} {
		var lines []string
		for _, p := range parts {
			lines = append(lines, p...)
		}
		text := strings.Join(lines, "\n")
		if agent.CheckPersonMessage(text) == nil || len(parts) == 1 {
			return text
		}
	}
	return ""
}

// labelText is s for a link's label, which may not hold Markdown
// characters: each of them becomes a hyphen.
func labelText(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("[]()<>`*_", r) || r < 0x20 || r == 0x7f {
			return '-'
		}
		return r
	}, s)
}

// personTime is how a person-facing message states a deadline.
const personTime = "2006-01-02 15:04 UTC"

func (e *pluginEnv) firstAgent(items []openedApproval) string {
	return items[0].group.opener()
}

// refusedSteps adds the steps of each reason a database refused for, once
// per reason, in the catalog's order.
func (e *pluginEnv) refusedSteps(b *agent.Steps, cmds agent.Commands, items []openedApproval, k plugin.EntryKey) {
	seen := map[string]bool{}
	enable := e.command("enable", append(entryArgs(k), "--"+flagApproveWithPasskey, "--json")...)
	for _, o := range items {
		if o.refused == nil || seen[o.refused.Reason] {
			continue
		}
		seen[o.refused.Reason] = true
		switch o.refused.Reason {
		case reasonTooManyPending:
			b.Stop("Stop: 8 plugin approvals already wait in that database.")
			b.AskPerson("Ask the person to sign the waiting plugin approvals or let them expire, 24 hours after each was opened; then run basalt plugin enable with --approve-with-passkey.")
		case reasonGuardOutdated:
			b.AgentRunCommand(cmds.Init(), guardUpdateText)
			if !cmds.AgentOperated() {
				b.TellAgent("Tell the agent once the guard is updated.")
				b.Stop("Stop until the person says the guard is updated, then run basalt plugin enable with --approve-with-passkey.")
			}
		case reasonUnknownAgent:
			b.MachineCommand(cmds, enable, "Once the entry names only agents of that database's guard, run this to open the missing approval.",
				"Once the person fixed the entry's agents, run this to open the missing approval.")
		default:
			b.AskPerson("Ask the person to check that the agent's database is up and reachable from this machine.")
			b.MachineCommand(cmds, enable, "Run this once the database answers: it opens the missing approval.",
				"Run this once the person says the database answers: it opens the missing approval.")
		}
	}
}

// handOver prints the result: with asJSON the result, else personMessage on
// stdout with each link on a line of its own. No restart: the engine starts
// the entry once its approval is signed. It returns exit 1 when a database
// refused.
func (e *pluginEnv) handOver(res approvalResult, asJSON bool) error {
	refused := slices.ContainsFunc(res.Approvals, func(a approvalItem) bool { return a.Refused != nil })
	if asJSON {
		printJSONValue(e.c, res)
	} else {
		for _, line := range strings.Split(res.PersonMessage, "\n") {
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				if err := printLink(e.c, e.c.stdout, line, linkRef{setting: "pagesUrl", item: "plugin approval", again: "basalt plugin enable"}); err != nil {
					return err
				}
				continue
			}
			fmt.Fprintln(e.c.stdout, line)
		}
	}
	if refused {
		return errApprovalRefused
	}
	return nil
}

// errApprovalRefused ends a command whose result names a database that
// could not open its approval: exit 1, the result already printed.
var errApprovalRefused = errors.New("a plugin approval could not be opened; the entry is written and waits for it")

// --- ending the old approval ---

// endApproval writes the PLUGIN_DISABLED agentName owes for k with its own
// credential, within 15 seconds (guard.EndPluginApproval); it returns why it
// could not, for a refusal's message.
func (e *pluginEnv) endApproval(k plugin.EntryKey, agentName string) (why string) {
	a, ok := agentOf(e.cfg, agentName)
	if !ok {
		return "it is not an agent of this engine"
	}
	dsn, err := e.ec.credential(a.Store.CredentialFile)
	if err != nil {
		return "its credential file cannot be read"
	}
	ctx, cancel := context.WithTimeout(e.c.ctx, databaseTimeout)
	defer cancel()
	conn, err := connect(ctx, dsn)
	if err != nil {
		return "its database does not answer (" + connectWhy(err) + ")"
	}
	defer func() { _ = conn.Close(context.WithoutCancel(e.c.ctx)) }()
	if err := guard.EndPluginApproval(ctx, conn, k.Name, k.Instance); err != nil {
		return "the old plugin approval could not be ended (" + pgDetail(err) + ")"
	}
	return ""
}

// endOwedApprovals writes, before the entry is written, the approval ends
// the agents owe for k (engine.PluginEndAgents), as the engine does for an
// engine-kept entry: an agent the entry did not serve, or no longer serves,
// never comes back on an old signature, even when the new approval cannot be
// opened afterwards. One that cannot be written refuses the command before
// anything is written; again is the refused command.
func (e *pluginEnv) endOwedApprovals(k plugin.EntryKey, prev *config.Plugin, next []string, again string) error {
	for _, name := range engine.PluginEndAgents(prev, next) {
		if why := e.endApproval(k, name); why != "" {
			return e.unreachable(name, why, again)
		}
	}
	return nil
}

// endAfterTurnOff ends the approvals of an entry just turned off, for its
// agents. Turning off is never blocked: an end that cannot be written is
// said, and stays owed to the next add or enable, which writes it first.
func (e *pluginEnv) endAfterTurnOff(p config.Plugin) {
	if !e.cfg.PluginRequiresApproval(p) {
		return
	}
	for _, name := range p.Agents {
		if why := e.endApproval(p.Key(), name); why != "" {
			fmt.Fprintf(e.c.stderr, "basalt: the signed approval of plugin %s was not ended for agent %s: %s. "+
				"The plugin is off; the next add or enable ends it before anything is written\n", p.Key(), name, why)
		}
	}
}

// --- add and enable ---

// addWithApproval is add in the approval flow: check, write, open, hand over.
func (e *pluginEnv) addWithApproval(f addFlags, prev *config.Plugin) error {
	again := e.againAdd(f, f.agents)
	if prev != nil && prev.ManifestSHA256 != "" {
		if done, err := e.narrowWithin(f, *prev); done || err != nil {
			return err
		}
	}
	if err := e.checkAgents(e.cfg, f.agents, func(a []string) string { return e.againAdd(f, a) }); err != nil {
		return err
	}
	// The databases first: staging makes the entry's directories, and a
	// refusal before the write leaves nothing behind.
	groups, err := e.approvalGroups(f.agents, again+" --"+flagApproveWithPasskey+" --json")
	if err != nil {
		return err
	}
	defer closeGroups(e.c.ctx, groups)
	staged, err := plugin.Stage(f.dir, e.root, f.instance, e.trust, e.mode, plugin.RequireApproval(true))
	if err != nil {
		return e.verifyRefusal(err, again)
	}
	defer func() { _ = staged.Discard() }()
	k := staged.Key
	if (prev == nil) != (e.cfg.PluginIndex(k) < 0) {
		return errChangedMeanwhile
	}
	// Ends owed first, before the entry is written: no refusal after the
	// write leaves an old approval to serve an agent that comes back.
	if err := e.endOwedApprovals(k, prev, f.agents, again+" --"+flagApproveWithPasskey+" --json"); err != nil {
		return err
	}
	shownSigner, shownKey := staged.Signer, staged.SignerKeyID
	var written config.Plugin
	err = e.update(config.Change{
		Apply: func(cfg *config.Config) error {
			i := cfg.PluginIndex(k)
			if (i >= 0) != (prev != nil) || (i >= 0 && !samePlugin(cfg.Plugins[i], *prev)) {
				return errChangedMeanwhile
			}
			if !e.approvalFlow(*cfg, prev, true) {
				return errChangedMeanwhile
			}
			if err := e.checkAgents(*cfg, f.agents, func(a []string) string { return e.againAdd(f, a) }); err != nil {
				return err
			}
			if _, err := staged.Commit(); err != nil {
				return e.verifyRefusal(err, again)
			}
			if staged.Signer != shownSigner || staged.SignerKeyID != shownKey {
				return fmt.Errorf("plugin %s: the installed copy's signer is not the one checked; nothing was written", k)
			}
			entry := config.Plugin{Name: k.Name, Instance: k.Instance}
			if i >= 0 {
				entry = cfg.Plugins[i]
			}
			entry.ManifestSHA256, entry.Agents, entry.Enabled, entry.Approval = staged.ManifestSHA256, f.agents, true, config.PluginApprovalRequired
			if _, err := entry.Entry(staged.Manifest); err != nil {
				return err
			}
			if i >= 0 {
				cfg.Plugins[i] = entry
			} else {
				cfg.Plugins = append(cfg.Plugins, entry)
			}
			written = entry
			return nil
		},
		Written: func(config.Config) { e.sweep(k, staged.ManifestSHA256) },
	})
	if err != nil {
		return err
	}
	items := e.openApprovals(groups, written, staged.Verified)
	res, err := e.approvalOutcome(k, staged.Manifest.Version, items)
	if err != nil {
		return err
	}
	return e.handOverOrWait(k, res, f.wait, f.asJSON)
}

// narrowWithin is add in the approval flow for an existing entry with the
// same manifest bytes that only removes agents: it needs no approval.
// done is false when the add does more (or nothing at all, which opens a
// new approval as enable would).
func (e *pluginEnv) narrowWithin(f addFlags, prev config.Plugin) (bool, error) {
	// A manifest that cannot be read is no narrowing: Stage refuses it.
	raw, readErr := readManifest(f.dir)
	narrows := readErr == nil && sha256Hex(raw) == prev.ManifestSHA256 && f.instance == prev.Key().Instance &&
		subset(f.agents, prev.Agents) && !sameSet(f.agents, prev.Agents)
	if !narrows {
		return false, nil
	}
	return true, e.narrowOnly(f, errChangedMeanwhile)
}

// enableWithApproval is enable in the approval flow: it opens a new
// approval for the installed copy and the entry as engine.json holds it,
// whether or not the entry is enabled.
func (e *pluginEnv) enableWithApproval(k plugin.EntryKey, p config.Plugin, wait int, asJSON bool) error {
	again := e.command("enable", entryArgs(k)...)
	v, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode, plugin.RequireApproval(true))
	if err != nil {
		return e.verifyRefusal(err, again)
	}
	if _, err := p.Entry(v.Manifest); err != nil {
		return err
	}
	groups, err := e.approvalGroups(p.Agents, again+" --"+flagApproveWithPasskey+" --json")
	if err != nil {
		return err
	}
	defer closeGroups(e.c.ctx, groups)
	if err := e.endOwedApprovals(k, &p, p.Agents, again+" --"+flagApproveWithPasskey+" --json"); err != nil {
		return err
	}
	var written config.Plugin
	err = e.update(config.Change{Apply: func(cfg *config.Config) error {
		i := cfg.PluginIndex(k)
		if i < 0 || !samePlugin(cfg.Plugins[i], p) || !e.approvalFlow(*cfg, &p, true) {
			return errChangedMeanwhile
		}
		now, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode, plugin.RequireApproval(true))
		if err != nil {
			return e.verifyRefusal(err, again)
		}
		if now.Signer != v.Signer || now.SignerKeyID != v.SignerKeyID {
			return errChangedMeanwhile
		}
		cfg.Plugins[i].Enabled, cfg.Plugins[i].Approval = true, config.PluginApprovalRequired
		written, v = cfg.Plugins[i], now
		return nil
	}})
	if err != nil {
		return err
	}
	items := e.openApprovals(groups, written, v)
	res, err := e.approvalOutcome(k, v.Manifest.Version, items)
	if err != nil {
		return err
	}
	return e.handOverOrWait(k, res, wait, asJSON)
}

// --- approve ---

// approvedJSON is basalt plugin approve --json.
type approvedJSON struct {
	ApprovalID string    `json:"approvalId"`
	Status     string    `json:"status"`
	ApprovedAt time.Time `json:"approvedAt"`
}

func pluginApprove(c *cliIO, args []string) int {
	fs := c.flags("plugin approve")
	agentName := fs.String("agent", "", "the agent that opened the approval (default: the one whose database holds it)")
	configPath, cfgErr := c.findConfig()
	if cfgErr != nil {
		return c.fail(cfgErr)
	}
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(positionalLast(fs, args)); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if fs.NArg() > 1 {
		return c.fail(fmt.Errorf("%w: give one basalt-plugin.1. code", errUsage))
	}
	if fs.NArg() == 0 && c.terminal == nil {
		// Nobody can answer a prompt here, and a read of stdin could wait
		// for ever: refuse before anything is read.
		return c.fail(fmt.Errorf("%w: give the code: basalt plugin approve <code>. It is asked for only at a terminal", errUsage))
	}
	var e *pluginEnv
	var err error
	if c.pluginViaSocket(configPath) {
		e, err = socketPluginEnv(c)
	} else {
		e, err = loadPluginEnv(c, configPath)
	}
	if err != nil {
		return c.fail(err)
	}
	if e.sock == nil && e.cfg.Service() {
		return c.fail(errApprovalInServiceMode("basalt plugin approve"))
	}
	code := fs.Arg(0)
	if code == "" {
		fmt.Fprint(c.stderr, "Paste the code the plugin approval page showed: ")
		if code, err = c.pasted(c.ctx); err != nil {
			return c.fail(err)
		}
	}
	resp, err := approval.ParsePluginResponse(code)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if e.sock != nil {
		return c.pluginDone(e.approveViaSocket(resp, *asJSON), *asJSON)
	}
	at, rec, err := e.relayPluginApproval(*agentName, resp)
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		return printJSONValue(c, approvedJSON{ApprovalID: resp.ApprovalID.String(), Status: "APPROVED", ApprovedAt: at.UTC()})
	}
	fmt.Fprintf(c.stderr, "basalt: plugin approval %s signed: plugin %s instance %s is approved; a running engine starts it within seconds\n", resp.ApprovalID, rec.Name, rec.Instance)
	return exitOK
}

// relayPluginApproval finds the agent that opened the approval (the one
// named, the only one, or the one whose database shows it the binding
// text), checks the code against the binding and the stored passkey for a
// clear message, and relays it to submit_plugin_approval, which checks it
// again in Postgres.
func (e *pluginEnv) relayPluginApproval(name string, resp approval.PluginApprovalResponse) (time.Time, guard.PluginApprovalRecord, error) {
	names := []string{name}
	if name == "" {
		names = agentNames(e.cfg)
	}
	var lastErr error
	for _, n := range names {
		conn, err := e.connectAgent(n)
		if err != nil {
			lastErr = err
			continue
		}
		at, rec, found, err := e.relayAs(conn, resp)
		_ = conn.Close(context.WithoutCancel(e.c.ctx))
		if found {
			return at, rec, err
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil && len(names) == 1 {
		return time.Time{}, guard.PluginApprovalRecord{}, lastErr
	}
	return time.Time{}, guard.PluginApprovalRecord{}, fmt.Errorf("no agent of this engine opened plugin approval %s; give --agent", resp.ApprovalID)
}

func (e *pluginEnv) relayAs(conn *pgx.Conn, resp approval.PluginApprovalResponse) (time.Time, guard.PluginApprovalRecord, bool, error) {
	ctx := e.c.ctx
	rec, ok, err := guard.ReadPluginApproval(ctx, conn, resp.ApprovalID)
	if err != nil {
		return time.Time{}, rec, false, fmt.Errorf("the plugin approvals cannot be read: %s", pgDetail(err))
	}
	if !ok || rec.BindingText == "" {
		return time.Time{}, rec, false, nil
	}
	keys, err := ledger.Passkeys(ctx, conn)
	if err != nil {
		return time.Time{}, rec, true, err
	}
	i := slices.IndexFunc(keys, func(k passkey.Credential) bool { return string(k.ID) == string(resp.CredentialID) })
	if i < 0 {
		return time.Time{}, rec, true, errors.New("the code was signed by a passkey this database does not know; nothing was approved")
	}
	if _, err := approval.VerifyPlugin(rec.BindingText, keys[i], resp); err != nil {
		return time.Time{}, rec, true, fmt.Errorf("the code does not verify, nothing was approved: %w", err)
	}
	at, err := guard.SubmitPluginApproval(ctx, conn, guard.PluginApprovalResponse{ApprovalID: resp.ApprovalID, Assertion: resp.Assertion()})
	if err != nil {
		return time.Time{}, rec, true, fmt.Errorf("the database refused the plugin approval: %s", pgDetail(err))
	}
	return at, rec, true, nil
}

// connectAgent connects with agent's credential within 15 seconds.
func (e *pluginEnv) connectAgent(name string) (*pgx.Conn, error) {
	return e.connectAgentCtx(e.c.ctx, name)
}

// connectAgentCtx is connectAgent within ctx too.
func (e *pluginEnv) connectAgentCtx(ctx context.Context, name string) (*pgx.Conn, error) {
	a, ok := agentOf(e.cfg, name)
	if !ok {
		return nil, errAgentNotInConfig(name, e.configPath)
	}
	dsn, err := e.ec.credential(a.Store.CredentialFile)
	if err != nil {
		return nil, fmt.Errorf("agent %s: its credential file cannot be read", name)
	}
	ctx, cancel := context.WithTimeout(ctx, databaseTimeout)
	defer cancel()
	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("agent %s: its database does not answer (%s)", name, connectWhy(err))
	}
	return conn, nil
}

// --- list ---

// Approval states basalt plugin list shows per agent.
const (
	stateApproved    = "APPROVED"
	statePending     = "PENDING"
	stateExpired     = "EXPIRED"
	stateEnded       = "ENDED"
	stateNone        = "NONE"
	stateUnavailable = "UNAVAILABLE"
	stateNotRequired = "NOT_REQUIRED"
)

// agentApproval is one agent's state of an entry's approval.
type agentApproval struct {
	Agent      string `json:"agent"`
	State      string `json:"state"`
	ApprovalID string `json:"approvalId,omitempty"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
}

type entryApproval struct {
	Required bool            `json:"required"`
	Agents   []agentApproval `json:"agents"`
}

// approvalReader reads each agent's plugin approvals once per command.
type approvalReader struct {
	e    *pluginEnv
	read map[string]agentRecords
}

type agentRecords struct {
	records []guard.PluginApprovalRecord
	ok      bool
}

func (r *approvalReader) records(name string) ([]guard.PluginApprovalRecord, bool) {
	if got, ok := r.read[name]; ok {
		return got.records, got.ok
	}
	got := agentRecords{}
	if conn, err := r.e.connectAgent(name); err == nil {
		ctx, cancel := context.WithTimeout(r.e.c.ctx, databaseTimeout)
		if st, err := guard.AgentStatus(ctx, conn, guard.Migrations()); err == nil && holdsPluginApprovals(st) {
			if recs, err := guard.ReadPluginApprovals(ctx, conn); err == nil {
				got = agentRecords{records: recs, ok: true}
			}
		}
		cancel()
		_ = conn.Close(context.WithoutCancel(r.e.c.ctx))
	}
	r.read[name] = got
	return got.records, got.ok
}

// approvalOf is entry p's approval state per listed agent; only an entry
// that requires approval reads a database.
func (r *approvalReader) approvalOf(p config.Plugin) entryApproval {
	out := entryApproval{Required: r.e.cfg.PluginRequiresApproval(p), Agents: []agentApproval{}}
	for _, name := range p.Agents {
		a := agentApproval{Agent: name, State: stateNotRequired}
		if out.Required {
			a = r.stateOf(name, p.Key())
		}
		out.Agents = append(out.Agents, a)
	}
	return out
}

func (r *approvalReader) stateOf(name string, k plugin.EntryKey) agentApproval {
	a := agentApproval{Agent: name, State: stateUnavailable}
	recs, ok := r.records(name)
	if !ok {
		return a
	}
	i := slices.IndexFunc(recs, func(rec guard.PluginApprovalRecord) bool { return rec.Name == k.Name && rec.Instance == k.Instance })
	if i < 0 {
		a.State = stateNone
		return a
	}
	rec := recs[i]
	a.ApprovalID = rec.ApprovalID.String()
	switch {
	case rec.Status == guard.PluginApprovalStatusApproved && rec.Ended():
		a.State = stateEnded
	case rec.Status == guard.PluginApprovalStatusApproved:
		a.State = stateApproved
	case rec.Status == guard.PluginApprovalStatusExpired, rec.Status == guard.PluginApprovalStatusPending && !r.e.c.now().Before(rec.ExpiresAt):
		a.State = stateExpired
	case rec.Status == guard.PluginApprovalStatusPending:
		a.State, a.ExpiresAt = statePending, rec.ExpiresAt.UTC().Format(time.RFC3339)
	default:
		a.State, a.ApprovalID = stateNone, ""
	}
	return a
}

// listedEntry is one entry of basalt plugin list --json.
type listedEntry struct {
	Name     string        `json:"name"`
	Instance string        `json:"instance"`
	Enabled  bool          `json:"enabled"`
	Agents   []string      `json:"agents"`
	Approval entryApproval `json:"approval"`
}

// writeApproval prints an entry's approval states under it.
func writeApproval(e *pluginEnv, a entryApproval) {
	if !a.Required {
		fmt.Fprintf(e.c.stdout, "  approval %s\n", stateNotRequired)
		return
	}
	for _, ag := range a.Agents {
		line := fmt.Sprintf("  approval %s %s", ag.Agent, ag.State)
		if ag.ExpiresAt != "" {
			line += " (expires " + ag.ExpiresAt + ")"
		}
		if ag.ApprovalID != "" {
			line += " " + ag.ApprovalID
		}
		fmt.Fprintln(e.c.stdout, line)
	}
}

// sha256Hex is the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string { return approval.SettingsHash(string(b)) }

// agentOf is the config's agent name.
func agentOf(cfg config.Config, name string) (config.Agent, bool) {
	i := slices.IndexFunc(cfg.Agents, func(a config.Agent) bool { return a.Name == name })
	if i < 0 {
		return config.Agent{}, false
	}
	return cfg.Agents[i], true
}

// existing is the entry add f would change, or nil for a new one: the
// entry named by the manifest in f.dir and f.instance. A manifest that
// cannot be read is a new entry here; Stage refuses it.
func (e *pluginEnv) existing(f addFlags) *config.Plugin {
	raw, err := readManifest(f.dir)
	if err != nil {
		return nil
	}
	m, err := plugin.ParseManifest(raw)
	if err != nil {
		return nil
	}
	i := e.cfg.PluginIndex(plugin.EntryKey{Name: m.Name, Instance: f.instance})
	if i < 0 {
		return nil
	}
	p := e.cfg.Plugins[i]
	return &p
}
