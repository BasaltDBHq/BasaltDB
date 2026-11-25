package plugin

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

func requestsKept() *KeptPlugins {
	return &KeptPlugins{ports: testPorts, agents: map[string]KeptAgent{
		"bot":   {host: "db", port: 5432, database: "app"},
		"other": {host: "db", port: 5432, database: "app"},
		"far":   {host: "db", port: 5432, database: "billing"},
	}}
}

// The caller always goes first, so the approval is opened with its own
// credential (requestedBy is the caller); a list without the caller, or
// with an agent on another database, is refused before anything is read.
func TestRequestAgentsStartWithTheCaller(t *testing.T) {
	t.Parallel()
	k := requestsKept()
	got, err := k.callerFirst("bot", []string{"other", "bot"})
	require.NoError(t, err)
	require.Equal(t, []string{"bot", "other"}, got)

	for _, agents := range [][]string{{"other"}, {"bot", "far"}} {
		_, err := k.callerFirst("bot", agents)
		var r *PluginRefusedError
		require.ErrorAs(t, err, &r, "%v", agents)
		require.Equal(t, ReasonPluginAgentNotAllowed, r.Reason)
	}
	// An unknown agent is PLUGIN_OPEN's to refuse (UNKNOWN_AGENT).
	got, err = k.callerFirst("bot", []string{"bot", "ghost"})
	require.NoError(t, err)
	require.Equal(t, []string{"bot", "ghost"}, got)
}

// The scope is the caller's OS user's agents, as the person socket gives
// that user; with no engine-kept plugins every call is refused.
func TestRequestReachIsTheCallersOSUser(t *testing.T) {
	t.Parallel()
	p := &Requests{uids: map[string]uint32{"bot": 501, "other": 501, "far": 777}, admitted: []uint32{501}}
	k, _, _, err := p.reach("bot")
	require.ErrorIs(t, err, errNoKept)
	require.Nil(t, k)

	p.kept.Store(requestsKept())
	_, uid, scope, err := p.reach("bot")
	require.NoError(t, err)
	require.Equal(t, uint32(501), uid)
	require.Equal(t, Scope{"bot": true, "other": true}, scope)

	_, err = p.OpenPlugin(context.Background(), "bot", PluginOpen{Name: "acme-ner", Instance: "default", Agents: []string{"other"}})
	var r *PluginRefusedError
	require.ErrorAs(t, err, &r)
	require.Equal(t, ReasonPluginAgentNotAllowed, r.Reason)

	// An agent whose OS user the person socket does not admit changes no
	// plugin, in any form, and reads no approval.
	for _, call := range []func() error{
		func() error {
			_, err := p.OpenPlugin(context.Background(), "far", PluginOpen{Name: "acme-ner", Instance: "default"})
			return err
		},
		func() error { return p.RemovePlugin(context.Background(), "far", "acme-ner", "default") },
		func() error {
			_, err := p.PluginApproval(context.Background(), "far", uuid.New())
			return err
		},
	} {
		r = nil
		require.ErrorAs(t, call(), &r)
		require.Equal(t, ReasonPluginAgentNotAllowed, r.Reason)
	}
}

// The wait's state: an approval is RUNNING only once every agent it names
// is served READY on it; ENDED once any of them ended or expired; an
// unknown id is not found in the entry.
func TestRequestApprovalState(t *testing.T) {
	t.Parallel()
	id, newer := uuid.New(), uuid.New()
	ptr := func(u uuid.UUID) *uuid.UUID { return &u }
	listed := func(states map[string]string, serving ...PersonPluginServing) PluginListed {
		l := PluginListed{Name: "acme-ner", Instance: "default", Source: SourceEngine, Serving: serving}
		for _, a := range []string{"bot", "other"} {
			l.Approval.Agents = append(l.Approval.Agents, PluginAgentStatus{Agent: a, State: states[a], ApprovalID: ptr(id)})
		}
		return l
	}
	approved := map[string]string{"bot": "APPROVED", "other": "APPROVED"}

	st, ok := approvalStateOf(listed(map[string]string{"bot": "PENDING", "other": "PENDING"}), id)
	require.True(t, ok)
	require.Equal(t, PluginStatePending, st.State)
	require.Equal(t, []string{"bot", "other"}, st.Agents)

	st, _ = approvalStateOf(listed(approved, PersonPluginServing{Agent: "bot", ApprovalID: ptr(id), Ready: true}), id)
	require.Equal(t, PluginStateApproved, st.State, "other is not served yet")

	st, _ = approvalStateOf(listed(approved,
		PersonPluginServing{Agent: "bot", ApprovalID: ptr(id), Ready: true},
		PersonPluginServing{Agent: "other", ApprovalID: ptr(id), Ready: false}), id)
	require.Equal(t, PluginStateApproved, st.State, "not READY")

	st, _ = approvalStateOf(listed(approved,
		PersonPluginServing{Agent: "bot", ApprovalID: ptr(id), Ready: true},
		PersonPluginServing{Agent: "other", ApprovalID: ptr(newer), Ready: true}), id)
	require.Equal(t, PluginStateApproved, st.State, "served on another approval")

	st, _ = approvalStateOf(listed(approved,
		PersonPluginServing{Agent: "bot", ApprovalID: ptr(id), Ready: true},
		PersonPluginServing{Agent: "other", ApprovalID: ptr(id), Ready: true}), id)
	require.Equal(t, PluginStateRunning, st.State)

	for _, ended := range []string{"ENDED", "EXPIRED"} {
		st, _ = approvalStateOf(listed(map[string]string{"bot": "APPROVED", "other": ended}), id)
		require.Equal(t, PluginStateEnded, st.State, ended)
	}

	_, ok = approvalStateOf(listed(approved), newer)
	require.False(t, ok)
}

// The person socket's errors become request_plugin's: a missing upload is
// an argument problem (call again with source), never NOT_FOUND.
func TestRequestErrors(t *testing.T) {
	t.Parallel()
	var r *PluginRefusedError
	require.ErrorAs(t, requestError(Refused("TOO_LARGE", "too large"), true), &r)
	require.Equal(t, "TOO_LARGE", r.Reason)
	require.ErrorAs(t, requestError(&PersonError{Code: CodeAgentNotAllowed, Message: "scope"}, false), &r)
	require.Equal(t, ReasonPluginAgentNotAllowed, r.Reason)
	var ae *guidance.ArgumentError
	require.ErrorAs(t, requestError(&PersonError{Code: CodeNotFound, Message: "gone"}, true), &ae)
	require.ErrorIs(t, requestError(&PersonError{Code: CodeNotFound, Message: "no entry"}, false), ErrPluginNotFound)
}
