package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// request_plugin (CONTRACT.md, MCP tools, request_plugin): the agent
// prepares a plugin install or change that the person approves on the
// plugin approval page, waits once for it, or removes a plugin. The agent
// never approves: nothing here signs, relays or holds a plugin signature.

const toolRequestPlugin = "request_plugin"

// The states of a request_plugin result.
const (
	PluginStatePending  = "PENDING"
	PluginStateApproved = "APPROVED"
	PluginStateRunning  = "RUNNING"
	PluginStateNarrowed = "NARROWED"
	PluginStateRemoved  = "REMOVED"
	PluginStateEnded    = "ENDED"
)

// codePluginRefused is a refused plugin change.
const codePluginRefused = "PLUGIN_REFUSED"

// PLUGIN_REFUSED reasons the tool gives itself; the engine's PluginRequests
// give the others (CONTRACT.md, Error codes).
const (
	ReasonPluginAgentOperated   = "AGENT_OPERATED"
	ReasonPluginSameUserMode    = "SAME_USER_MODE"
	ReasonPluginNoLocalPages    = "NO_LOCAL_PAGES"
	ReasonPluginAgentNotAllowed = "AGENT_NOT_ALLOWED"
	reasonPluginBadManifest     = "BAD_MANIFEST"
	reasonPluginNotTrusted      = "NOT_TRUSTED"
	reasonPluginUnknownAgent    = "UNKNOWN_AGENT"
	reasonPluginUnreachable     = "DATABASE_UNREACHABLE"
	reasonPluginUnsafePath      = "UNSAFE_PATH"
)

// PluginRequests serve request_plugin with the engine's engine-kept plugin
// entries (CONTRACT.md, Plugin approval in service mode). caller is the
// agent that calls; every method applies its OS user's scope. Errors are
// *PluginRefusedError, ErrPluginNotFound or *ArgumentError; anything else is
// INTERNAL.
type PluginRequests interface {
	// OpenPlugin is PLUGIN_OPEN for caller: the uploaded copy, or the
	// installed one when p.UploadID is nil.
	OpenPlugin(ctx context.Context, caller string, p PluginOpen) (PluginOpened, error)
	// RemovePlugin is PLUGIN_REMOVE for caller.
	RemovePlugin(ctx context.Context, caller, name, instance string) error
	// PluginApproval is the state of approval id, as PLUGIN_LIST shows the
	// entry that holds it to caller, and what the engine serves of it.
	PluginApproval(ctx context.Context, caller string, id uuid.UUID) (PluginApprovalState, error)
	// DropUpload removes caller's upload id of a call refused before the
	// engine took it, so no refusal holds one of its few open uploads.
	DropUpload(caller string, id uuid.UUID)
}

// PluginOpen is one request to open a plugin approval.
type PluginOpen struct {
	// UploadID is the upload basalt mcp made of the source; nil opens a new
	// approval for the installed copy.
	UploadID    *uuid.UUID
	Name        string
	Instance    string
	Executables []string
	// Agents is the entry's full new list; nil is the default: the caller
	// alone for a new entry, the entry's agents for an existing one.
	Agents []string
}

// PluginOpened is an approval opened, or a narrowing applied.
type PluginOpened struct {
	Name, Instance, Version string
	Agents                  []string
	Narrowed                bool
	ApprovalID              uuid.UUID
	ExpiresAt               time.Time
	BindingText             string
}

// PluginApprovalState is one approval as the wait reads it. State is
// PENDING, APPROVED, RUNNING or ENDED.
type PluginApprovalState struct {
	Name, Instance string
	Agents         []string
	State          string
	ExpiresAt      time.Time
}

// PluginRefusedError is PLUGIN_REFUSED with its reason, from the engine.
type PluginRefusedError struct {
	Reason, Message string
}

func (r *PluginRefusedError) Error() string { return r.Message }

// ErrPluginNotFound: no entry, or no approval, the caller may reach.
var ErrPluginNotFound = errors.New("the engine keeps no such plugin or plugin approval for this agent")

// requestPluginArgs is the request_plugin tool's input
// (api/mcp/tools/request_plugin.json).
type requestPluginArgs struct {
	Source          string   `json:"source" validate:"omitempty,min=2,max=4096,startswith=/"`
	Name            string   `json:"name" validate:"omitempty,max=40"`
	Instance        string   `json:"instance" validate:"omitempty,max=32"`
	Agents          []string `json:"agents" validate:"omitempty,min=1,max=256,unique,dive,max=63"`
	Remove          *bool    `json:"remove"`
	ApprovalID      string   `json:"approvalId" validate:"omitempty,uuid"`
	WaitForApproval *int     `json:"waitForApproval" validate:"omitempty,min=0,max=110"`
}

// requestPluginResult is its output.
type requestPluginResult struct {
	State         string         `json:"state"`
	Name          string         `json:"name"`
	Instance      string         `json:"instance"`
	Version       string         `json:"version,omitempty"`
	Agents        []string       `json:"agents,omitempty"`
	ApprovalID    string         `json:"approvalId,omitempty"`
	ExpiresAt     string         `json:"expiresAt,omitempty"`
	ApprovalURL   string         `json:"approvalUrl,omitempty"`
	PersonMessage string         `json:"personMessage"`
	Links         []mcp.Link     `json:"links,omitempty"`
	NextSteps     []mcp.NextStep `json:"nextSteps"`
}

const pluginDefaultInstanceName = "default"

func (h handlers) requestPlugin(ctx context.Context, raw json.RawMessage) (any, error) {
	var args requestPluginArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if err := args.check(); err != nil {
		return nil, err
	}
	return h.svc.RequestPlugin(ctx, args, mcp.Meta(ctx))
}

// check holds the call to exactly one form.
func (a requestPluginArgs) check() error {
	forms := 0
	for _, given := range []bool{a.Source != "", a.Name != "", a.ApprovalID != ""} {
		if given {
			forms++
		}
	}
	remove := a.Remove != nil && *a.Remove
	switch {
	case forms != 1:
		return &ArgumentError{Message: "name exactly one of source, name or approvalId"}
	case a.ApprovalID != "" && (a.Instance != "" || a.Agents != nil || a.Remove != nil):
		return &ArgumentError{Message: "approvalId takes nothing but waitForApproval"}
	case a.ApprovalID == "" && a.WaitForApproval != nil:
		return &ArgumentError{Message: "waitForApproval is only for approvalId"}
	case a.Remove != nil && a.Name == "":
		return &ArgumentError{Message: "remove is only for name"}
	case remove && a.Agents != nil:
		return &ArgumentError{Message: "remove takes no agents: the plugin stops for every agent it served"}
	}
	return nil
}

// RequestPlugin serves request_plugin. meta is the call's _meta, which
// carries basalt mcp's upload for source.
func (s *Service) RequestPlugin(ctx context.Context, a requestPluginArgs, meta json.RawMessage) (requestPluginResult, error) {
	instance := a.Instance
	if instance == "" {
		instance = pluginDefaultInstanceName
	}
	remove := a.Remove != nil && *a.Remove
	if err := s.pluginsServed(a.ApprovalID == "" && !remove); err != nil {
		if up, upErr := uploadOf(meta); a.Source != "" && upErr == nil && s.PluginRequests != nil {
			s.PluginRequests.DropUpload(s.Name, uuid.MustParse(up.UploadID))
		}
		return requestPluginResult{}, err
	}
	if a.ApprovalID != "" {
		wait := DefaultApprovalWait
		if a.WaitForApproval != nil {
			wait = time.Duration(*a.WaitForApproval) * time.Second
		}
		return s.waitPlugin(ctx, uuid.MustParse(a.ApprovalID), wait)
	}
	if remove {
		if err := s.PluginRequests.RemovePlugin(ctx, s.Name, a.Name, instance); err != nil {
			return requestPluginResult{}, s.pluginError(err)
		}
		return pluginDone(PluginStateRemoved, a.Name, instance,
			fmt.Sprintf("The plugin %s/%s is removed: it stopped, and adding it again needs your approval.", a.Name, instance),
			"Tell the person the plugin is removed.")
	}
	open := PluginOpen{Name: a.Name, Instance: instance, Agents: a.Agents}
	if a.Source != "" {
		up, err := uploadOf(meta)
		if err != nil {
			return requestPluginResult{}, err
		}
		id := uuid.MustParse(up.UploadID)
		open.UploadID, open.Name, open.Executables = &id, up.Name, up.Executables
	}
	opened, err := s.PluginRequests.OpenPlugin(ctx, s.Name, open)
	if err != nil {
		return requestPluginResult{}, s.pluginError(err)
	}
	if opened.Narrowed {
		res, err := pluginDone(PluginStateNarrowed, opened.Name, opened.Instance,
			fmt.Sprintf("The plugin %s/%s now serves only %s. Nothing needs your approval: removing agents never widens what it gets.",
				opened.Name, opened.Instance, joinNames(opened.Agents)),
			"Tell the person the plugin now serves only the agents named.")
		res.Version, res.Agents = opened.Version, opened.Agents
		return res, err
	}
	return s.pluginOpened(ctx, opened)
}

// pluginsServed refuses request_plugin where it is not served: an
// agent-operated engine, a same-user engine, and, for a call that opens an
// approval, an engine that serves no local pages.
func (s *Service) pluginsServed(opens bool) error {
	switch {
	case s.Commands.AgentOperated():
		return pluginRefused(ReasonPluginAgentOperated,
			"request_plugin is refused: this engine is operated by an agent, and plugin changes stay refused there until remote installation exists. Nothing was written",
			"Plugins cannot be added or changed on an engine an agent operates yet. Nothing was changed.")
	case s.SameUser || s.PluginRequests == nil:
		return pluginRefused(ReasonPluginSameUserMode,
			"request_plugin is refused: this engine runs as the person's own OS user and keeps no plugins of its own. Nothing was written",
			"This Basalt engine runs as your own user, so it keeps no plugins it could add for you. A plugin is added to its engine.json by hand.")
	case opens && s.PagesOrigin == "":
		return pluginRefused(ReasonPluginNoLocalPages,
			"request_plugin is refused: this engine serves no local pages, so there is no page to approve the plugin on. Nothing was written",
			"This Basalt engine serves no approval pages on this computer, so you could not approve a plugin. Turn its local pages on first.")
	}
	return nil
}

// uploadOf is basalt mcp's upload of the source, from the call's _meta.
func uploadOf(meta json.RawMessage) (mcp.PluginUpload, error) {
	missing := &ArgumentError{Message: "basalt mcp handed over no plugin files for source (or the engine dropped them when it restarted); call request_plugin again with source"}
	var m map[string]json.RawMessage
	if len(meta) == 0 || json.Unmarshal(meta, &m) != nil || m[mcp.MetaPluginUpload] == nil {
		return mcp.PluginUpload{}, missing
	}
	var up mcp.PluginUpload
	if json.Unmarshal(m[mcp.MetaPluginUpload], &up) != nil || up.Name == "" {
		return mcp.PluginUpload{}, missing
	}
	if _, err := uuid.Parse(up.UploadID); err != nil {
		return mcp.PluginUpload{}, missing
	}
	return up, nil
}

// pluginOpened hands over a new approval: the short link on the engine's
// local pages, the person's message with the page's level line, and the
// steps (CONTRACT.md, Plugin approval links).
func (s *Service) pluginOpened(ctx context.Context, o PluginOpened) (requestPluginResult, error) {
	b, err := approval.ParsePluginBinding(o.BindingText)
	if err != nil {
		return requestPluginResult{}, err
	}
	link, err := s.issuedLink(links.PluginApproval, o.ApprovalID, o.ExpiresAt)
	if err != nil {
		return requestPluginResult{}, err
	}
	level := pluginLevel(b)
	lead := fmt.Sprintf("%s asks you to approve the plugin %s %s.", s.Name, o.Name, o.Version)
	if len(b.Change) > 0 {
		lead = fmt.Sprintf("%s asks you to approve a change to the plugin %s %s.", s.Name, o.Name, o.Version)
	}
	ask := "Approve it with your passkey:"
	if level == pluginLevelUnfenced {
		ask = "Approve it with your passkey only if you know who made it:"
	}
	var lines []string
	steps := NewSteps()
	if ids, err := s.credentialIDs(ctx); err == nil && len(ids) == 0 {
		lines = append(lines, "Nobody can approve this yet: no passkey is registered for this database.")
		noPasskeySteps(steps, s.Commands)
	}
	lines = append(lines, lead, pluginLevelLine(level), ask, "", link, "",
		fmt.Sprintf("Expires %s. The plugin starts within seconds of your approval.", o.ExpiresAt.UTC().Format(personTime)))
	steps.OpenLink(link, "Open the link, read what the plugin may do and approve it with your passkey.").
		CallTool(toolRequestPlugin, map[string]any{"approvalId": o.ApprovalID.String()},
			fmt.Sprintf("Show the person personMessage first. Then, in the same turn, call this once: it returns as soon as the plugin runs, or after %d seconds.", int(DefaultApprovalWait/time.Second)))
	built, err := steps.Build()
	if err != nil {
		return requestPluginResult{}, err
	}
	return requestPluginResult{
		State: PluginStatePending, Name: o.Name, Instance: o.Instance, Version: o.Version, Agents: o.Agents,
		ApprovalID: o.ApprovalID.String(), ExpiresAt: timeText(o.ExpiresAt), ApprovalURL: link,
		PersonMessage: strings.Join(lines, "\n"), Links: []mcp.Link{{Label: "Approve the plugin " + o.Name, URL: link}},
		NextSteps: built,
	}, nil
}

// waitPlugin is the wait form: it reads the approval about once a second
// until the engine runs the plugin on it, it is no longer open, or wait is
// up. It only reads.
func (s *Service) waitPlugin(ctx context.Context, id uuid.UUID, wait time.Duration) (requestPluginResult, error) {
	deadline := s.Now().Add(wait)
	for {
		st, err := s.PluginRequests.PluginApproval(ctx, s.Name, id)
		if errors.Is(err, ErrPluginNotFound) {
			st, err = s.endedPluginApproval(ctx, id)
		}
		if err != nil {
			return requestPluginResult{}, s.pluginError(err)
		}
		done := st.State == PluginStateRunning || st.State == PluginStateEnded
		if done || !s.Now().Add(s.Poll).Before(deadline) {
			return s.pluginWaited(id, st, wait > 0)
		}
		select {
		case <-ctx.Done():
			return requestPluginResult{}, ctx.Err()
		case <-time.After(s.Poll):
		}
	}
}

// endedPluginApproval is approval id when no entry holds it any more (the
// plugin was removed, or a newer approval replaced it for every agent): an
// approval the caller's role opened or that names it reads ENDED, anything
// else is not found.
func (s *Service) endedPluginApproval(ctx context.Context, id uuid.UUID) (PluginApprovalState, error) {
	if s.PluginApprovals == nil {
		return PluginApprovalState{}, ErrPluginNotFound
	}
	r, ok, err := s.PluginApprovals.ReadPluginApproval(ctx, id)
	switch {
	case err != nil:
		return PluginApprovalState{}, err
	case !ok:
		return PluginApprovalState{}, ErrPluginNotFound
	}
	return PluginApprovalState{Name: r.Name, Instance: r.Instance, State: PluginStateEnded}, nil
}

// pluginWaited is the wait form's answer for st.
func (s *Service) pluginWaited(id uuid.UUID, st PluginApprovalState, waited bool) (requestPluginResult, error) {
	entry := st.Name + "/" + st.Instance
	again := map[string]any{"name": st.Name, "instance": st.Instance}
	steps := NewSteps()
	var msg string
	switch st.State {
	case PluginStateRunning:
		msg = "The plugin " + entry + " is approved and running."
		steps.Stop("Tell the person the plugin runs.")
	case PluginStateApproved:
		msg = "You approved the plugin " + entry + ". It does not run yet; the agent checks why."
		steps.CallTool(toolStatus, map[string]any{}, "Call status: its plugins and problems say why the plugin does not run yet.")
	case PluginStateEnded:
		msg = "The approval of the plugin " + entry + " is over: it expired, a newer one replaced it, or the plugin was turned off or removed. Nothing runs on it."
		steps.AskPerson("Ask the person whether to ask for the plugin again.").
			CallTool(toolRequestPlugin, again, "When they want it, call this: it opens a new approval for the installed plugin.")
	default:
		msg = fmt.Sprintf("The plugin %s waits for your approval. Open the link the agent gave you and approve it with your passkey before %s; tell the agent once you did.",
			entry, st.ExpiresAt.UTC().Format(personTime))
		wait := 0
		steps.OpenGivenLink("Open the plugin approval link the agent gave you and approve it with your passkey.").
			TellAgent("Tell the agent once you approved.").
			EndTurn("Do not wait again in this turn: the person may take long. End your turn with the link and its expiry.").
			CallTool(toolRequestPlugin, map[string]any{"approvalId": id.String(), "waitForApproval": wait},
				"When the person says they approved, call this once: it answers at once.")
		if !waited {
			msg = "The plugin " + entry + " waits for your approval."
		}
	}
	built, err := steps.Build()
	if err != nil {
		return requestPluginResult{}, err
	}
	res := requestPluginResult{
		State: st.State, Name: st.Name, Instance: st.Instance, Agents: st.Agents, ApprovalID: id.String(),
		PersonMessage: msg, NextSteps: built,
	}
	if st.State == PluginStatePending && !st.ExpiresAt.IsZero() {
		res.ExpiresAt = timeText(st.ExpiresAt)
	}
	return res, nil
}

// pluginDone is a result that only tells the person.
func pluginDone(state, name, instance, msg, text string) (requestPluginResult, error) {
	built, err := NewSteps().Stop(text).Build()
	if err != nil {
		return requestPluginResult{}, err
	}
	return requestPluginResult{State: state, Name: name, Instance: instance, PersonMessage: msg, NextSteps: built}, nil
}

// pluginError maps the engine's answer to the tool's error body, with the
// catalog's steps for each PLUGIN_REFUSED reason.
func (s *Service) pluginError(err error) error {
	var r *PluginRefusedError
	switch {
	case errors.Is(err, ErrPluginNotFound):
		return &mcp.ToolError{Code: CodeNotFound, Message: err.Error()}
	case errors.As(err, &r):
		return pluginRefused(r.Reason, r.Message, "Basalt did not add or change the plugin: "+r.Message)
	}
	return err
}

// pluginRefused is PLUGIN_REFUSED with the steps the catalog gives its
// reason.
func pluginRefused(reason, message, person string) error {
	steps := NewSteps()
	switch reason {
	case reasonPluginBadManifest, reasonPluginNotTrusted:
		steps.Stop("Stop: the plugin's files were refused; its publisher must fix them.")
	case reasonPluginUnknownAgent:
		steps.ReviseCall(toolRequestPlugin, nil, "Call again with agents naming only this engine's agents.")
	case reasonPluginUnreachable:
		steps.AskPerson("Ask the person to check that the database is up.").
			CallTool(toolRequestPlugin, nil, "Once it answers, call request_plugin again (with name and instance when the plugin is already installed).")
	default:
		steps.Stop("Stop: the engine refused this plugin change; do not work around it.").
			AskPerson("Show the person the personMessage; only they can decide about this plugin.")
	}
	built, err := steps.Build()
	if err != nil {
		return err
	}
	return &mcp.ToolError{Code: codePluginRefused, Reason: reason, Message: message, PersonMessage: person, NextSteps: built}
}

// The page's three levels, from calm to the strong warning (CONTRACT.md,
// The plugin approval page).
const (
	pluginLevelPublished = 1 + iota
	pluginLevelFenced
	pluginLevelUnfenced
)

// The page's level lines: personMessage carries the same words, so an
// honest agent relays the warning; the page is the protection.
const (
	pluginLevelKnown       = "Published by Basalt."
	pluginLevelUnknown     = "Nobody vouches for this plugin. Add it only if you trust where it came from."
	pluginLevelUnknownHere = "Nobody vouches for this plugin. It runs a stranger's program on the computer Basalt runs on, with the same " +
		"access as Basalt itself, so it could read your database password and the key Basalt uses to hide private values."
)

// pluginLevel is the page's level of a binding, from signer, endpoint and
// isolation, as the page derives it.
func pluginLevel(b approval.PluginBinding) int {
	if b.Signer == guard.PluginSignerKnown {
		return pluginLevelPublished
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
		return pluginLevelFenced
	}
	return pluginLevelUnfenced
}

func pluginLevelLine(level int) string {
	switch level {
	case pluginLevelPublished:
		return pluginLevelKnown
	case pluginLevelFenced:
		return pluginLevelUnknown
	}
	return pluginLevelUnknownHere
}

func joinNames(names []string) string {
	return strings.Join(slices.Sorted(slices.Values(names)), ", ")
}
