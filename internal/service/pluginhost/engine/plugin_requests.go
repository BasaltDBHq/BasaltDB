package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/person"
)

// Requests serve the agents' request_plugin calls with the
// engine-kept entries (CONTRACT.md, MCP tools, request_plugin): the person
// socket's PLUGIN_OPEN, PLUGIN_REMOVE and PLUGIN_LIST, run in process for
// the calling agent's OS user and that user's scope (SM-4). The engine-kept
// plugins exist only once the agents serve, so kept is set then; until it
// is, and on an engine whose store could not be opened, every call is
// refused.
type Requests struct {
	kept atomic.Pointer[KeptPlugins]
	// uids is every configured agent's OS user id.
	uids map[string]uint32
	// admitted are the OS users the person socket admits (personUids):
	// only an agent running as one of them may change plugins, as over the
	// socket itself.
	admitted []uint32
}

var _ agent.PluginRequests = (*Requests)(nil)

// errNoKept is the refusal while the engine keeps no plugins of its own.
var errNoKept error = &agent.PluginRefusedError{
	Reason:  reasonUnsafePath,
	Message: "the engine keeps no plugins of its own: its state directory cannot hold them (the engine's log says why). Nothing was written",
}

const reasonUnsafePath = "UNSAFE_PATH"

// reach is the caller's OS user and the agents that user runs: what the
// person socket would let that user change.
func (p *Requests) reach(caller string) (*KeptPlugins, uint32, person.Scope, error) {
	k := p.kept.Load()
	if k == nil {
		return nil, 0, nil, errNoKept
	}
	uid, ok := p.uids[caller]
	if !ok {
		return nil, 0, nil, fmt.Errorf("agent %s has no OS user", caller)
	}
	if !slices.Contains(p.admitted, uid) {
		return nil, 0, nil, &agent.PluginRefusedError{Reason: agent.ReasonPluginAgentNotAllowed, Message: fmt.Sprintf(
			"agent %s runs as an OS user (uid %d) the engine does not let change plugins: only the person's own users may. Nothing was written", caller, uid)}
	}
	scope := person.Scope{}
	for name, u := range p.uids {
		if u == uid {
			scope[name] = true
		}
	}
	return k, uid, scope, nil
}

// OpenPlugin opens one approval, in the caller's own database, with the
// caller's own credential: the caller goes first in agents, and every agent
// must use the caller's database, so the approval's requestedBy is the
// caller and the page lists exactly the agents the plugin will serve.
func (p *Requests) OpenPlugin(ctx context.Context, caller string, o agent.PluginOpen) (agent.PluginOpened, error) {
	k, uid, scope, err := p.reach(caller)
	if err != nil {
		return agent.PluginOpened{}, err
	}
	key := pluginmodel.EntryKey{Name: o.Name, Instance: o.Instance}
	agents := o.Agents
	if agents == nil {
		agents = k.agentsOf(key, caller)
	}
	agents, err = k.callerFirst(caller, agents)
	if err != nil {
		k.dropUpload(uid, o.UploadID)
		return agent.PluginOpened{}, err
	}
	res, err := k.Open(ctx, uid, scope, person.PluginOpenParams{
		UploadID: o.UploadID, Name: o.Name, Instance: o.Instance, Agents: agents, Executables: o.Executables,
	})
	if err != nil {
		// A refusal before PLUGIN_OPEN took the upload (its scope check)
		// leaves it; one it took is gone already.
		k.dropUpload(uid, o.UploadID)
		return agent.PluginOpened{}, requestError(err, o.UploadID != nil)
	}
	out := agent.PluginOpened{Name: res.Name, Instance: res.Instance, Version: res.Version, Agents: agents, Narrowed: res.Narrowed}
	if res.Narrowed {
		return out, nil
	}
	if len(res.Approvals) != 1 {
		return agent.PluginOpened{}, fmt.Errorf("plugin %s: %d approvals opened, want one", key, len(res.Approvals))
	}
	a := res.Approvals[0]
	switch {
	case a.Refused != nil:
		return agent.PluginOpened{}, &agent.PluginRefusedError{Reason: a.Refused.Reason, Message: a.Refused.Message}
	case a.ApprovalID == nil || a.ExpiresAt == nil:
		return agent.PluginOpened{}, fmt.Errorf("plugin %s: an approval without its id", key)
	}
	out.ApprovalID, out.ExpiresAt, out.BindingText = *a.ApprovalID, *a.ExpiresAt, a.BindingText
	return out, nil
}

// DropUpload removes caller's upload id; nothing when there is none.
func (p *Requests) DropUpload(caller string, id uuid.UUID) {
	k := p.kept.Load()
	uid, ok := p.uids[caller]
	if k == nil || !ok {
		return
	}
	k.dropUpload(uid, &id)
}

// RemovePlugin removes an engine-kept entry for the caller.
func (p *Requests) RemovePlugin(ctx context.Context, caller, name, instance string) error {
	k, _, scope, err := p.reach(caller)
	if err != nil {
		return err
	}
	if _, err := k.Remove(ctx, scope, person.PluginEntryParams{Name: name, Instance: instance}); err != nil {
		return requestError(err, false)
	}
	return nil
}

// PluginApproval is approval id's state for the wait: the newest approval
// of each agent of the engine-kept entry that holds it, as PLUGIN_LIST reads
// them, and whether the engine serves the entry READY on it to every agent
// it names. An agent whose approvals could not be read decides nothing: the
// approval stays PENDING (or APPROVED) until it can be read.
func (p *Requests) PluginApproval(ctx context.Context, caller string, id uuid.UUID) (agent.PluginApprovalState, error) {
	k, _, scope, err := p.reach(caller)
	if err != nil {
		return agent.PluginApprovalState{}, err
	}
	list, err := k.List(ctx, scope)
	if err != nil {
		return agent.PluginApprovalState{}, requestError(err, false)
	}
	for _, l := range list.Plugins {
		if l.Source != person.SourceEngine {
			continue
		}
		if st, ok := approvalStateOf(l, id); ok {
			return st, nil
		}
	}
	return agent.PluginApprovalState{}, agent.ErrPluginNotFound
}

// approvalStateOf is id's state in entry l; false when no agent of l has
// id as its newest approval.
func approvalStateOf(l person.PluginListed, id uuid.UUID) (agent.PluginApprovalState, bool) {
	st := agent.PluginApprovalState{Name: l.Name, Instance: l.Instance, State: agent.PluginStateApproved}
	unread := false
	for _, a := range l.Approval.Agents {
		if a.State == approvalStateUnavailable {
			unread = true
		}
		if a.ApprovalID == nil || *a.ApprovalID != id {
			continue
		}
		st.Agents = append(st.Agents, a.Agent)
		switch {
		case a.State == "ENDED" || a.State == "EXPIRED" || st.State == agent.PluginStateEnded:
			st.State = agent.PluginStateEnded
		case a.State == "PENDING" || st.State == agent.PluginStatePending:
			st.State = agent.PluginStatePending
			if a.ExpiresAt != nil {
				st.ExpiresAt = *a.ExpiresAt
			}
		}
	}
	if len(st.Agents) == 0 {
		return st, false
	}
	if st.State == agent.PluginStateApproved && !unread && servedOn(l, id, st.Agents) {
		st.State = agent.PluginStateRunning
	}
	return st, true
}

// servedOn: the engine serves l, READY, to every one of agents on approval
// id.
func servedOn(l person.PluginListed, id uuid.UUID, agents []string) bool {
	for _, name := range agents {
		if !slices.ContainsFunc(l.Serving, func(s person.PluginServing) bool {
			return s.Agent == name && s.Ready && s.ApprovalID != nil && *s.ApprovalID == id
		}) {
			return false
		}
	}
	return true
}

// agentsOf is the default agents of a request: the entry's agents when the
// engine keeps it, else the caller alone, never every agent.
func (s *KeptPlugins) agentsOf(k pluginmodel.EntryKey, caller string) []string {
	entries, err := s.store.Entries(s.cfg)
	if err == nil {
		if i := keptIndex(entries, k); i >= 0 && len(entries[i].Agents) > 0 {
			return slices.Clone(entries[i].Agents)
		}
	}
	return []string{caller}
}

// callerFirst puts the caller first in agents, so its database's approval
// is opened with its own credential, and refuses a list without the caller
// or with an agent on another database. An agent the engine does not have
// is left for PLUGIN_OPEN to refuse (UNKNOWN_AGENT).
func (s *KeptPlugins) callerFirst(caller string, agents []string) ([]string, error) {
	if !slices.Contains(agents, caller) {
		return nil, &agent.PluginRefusedError{Reason: agent.ReasonPluginAgentNotAllowed, Message: fmt.Sprintf(
			"agents must include you (%s): an agent asks for a plugin for itself, and for other agents only beside itself. Nothing was written", caller)}
	}
	own, ok := s.agents[caller]
	if !ok {
		return nil, fmt.Errorf("agent %s has no credential", caller)
	}
	out := []string{caller}
	for _, a := range agents {
		if a == caller {
			continue
		}
		if other, known := s.agents[a]; known && (other.host != own.host || other.port != own.port || other.database != own.database) {
			return nil, &agent.PluginRefusedError{Reason: agent.ReasonPluginAgentNotAllowed, Message: fmt.Sprintf(
				"agent %s uses another database than yours: list only agents of your own database, each other database's agent asks for itself. Nothing was written", a)}
		}
		out = append(out, a)
	}
	return out, nil
}

// dropUpload removes the caller's upload id of a request refused before
// PLUGIN_OPEN took it, so a refused call does not hold one of the engine's
// few open uploads until it expires.
func (s *KeptPlugins) dropUpload(uid uint32, id *uuid.UUID) {
	if id == nil {
		return
	}
	if t, err := s.store.Take(uid, *id); err == nil {
		t.Release()
	}
}

// requestError maps the person socket's errors to request_plugin's. A
// NOT_FOUND upload is gone (the engine dropped it, or it expired): call
// again with source.
func requestError(err error, upload bool) error {
	var pe *person.Error
	if !errors.As(err, &pe) {
		return err
	}
	switch pe.Code {
	case person.CodePluginRefused:
		return &agent.PluginRefusedError{Reason: pe.Reason, Message: pe.Message}
	case person.CodeAgentNotAllowed:
		return &agent.PluginRefusedError{Reason: agent.ReasonPluginAgentNotAllowed, Message: pe.Message}
	case person.CodeNotFound:
		if upload {
			return &agent.ArgumentError{Message: "the plugin's files are no longer on the engine (it restarted, or 15 minutes passed): call request_plugin again with source"}
		}
		return agent.ErrPluginNotFound
	case person.CodeInvalidArgument:
		return &agent.ArgumentError{Message: pe.Message}
	case person.CodeUIDNotAllowed, person.CodeUnknownAgent, person.CodeUnknownMethod, person.CodeRefused, person.CodeInternal:
	}
	return err
}

// UploadBegin is the upload method that opens an upload of a plugin's files
// (CONTRACT.md, MCP tools, request_plugin), called on caller's own socket by
// basalt mcp on a second connection. The agent's socket admits only its own
// OS user, the upload belongs to that user, and the caller is refused as
// request_plugin refuses an install (served, then reach) before anything is
// written. The errors are the request's (agent.PluginRefusedError and the
// like); the transport maps them.
func (p *Requests) UploadBegin(ctx context.Context, caller string, served func() error) (person.PluginUploadBeginResult, error) {
	k, uid, err := p.admitUpload(caller, served)
	if err != nil {
		return person.PluginUploadBeginResult{}, err
	}
	out, err := k.UploadBegin(ctx, uid)
	if err != nil {
		return person.PluginUploadBeginResult{}, requestError(err, false)
	}
	return out, nil
}

// UploadPart is the upload method that adds a part of a file to an upload;
// raw is its parameters, which are decoded strictly.
func (p *Requests) UploadPart(ctx context.Context, caller string, served func() error, raw json.RawMessage) (person.PluginUploadPartResult, error) {
	k, uid, err := p.admitUpload(caller, served)
	if err != nil {
		return person.PluginUploadPartResult{}, err
	}
	var in person.PluginUploadPartParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || in.UploadID == uuid.Nil || in.Path == "" {
		return person.PluginUploadPartResult{}, &agent.ArgumentError{Message: "a part needs uploadId, path, offset and data, and nothing else"}
	}
	out, err := k.UploadPart(ctx, uid, in)
	if err != nil {
		return person.PluginUploadPartResult{}, requestError(err, false)
	}
	return out, nil
}

func (p *Requests) admitUpload(caller string, served func() error) (*KeptPlugins, uint32, error) {
	if err := served(); err != nil {
		return nil, 0, err
	}
	k, uid, _, err := p.reach(caller)
	return k, uid, err
}
