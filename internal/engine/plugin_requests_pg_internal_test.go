//go:build unix

package engine

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

// request_plugin on a real guard: the caller's upload opens one approval
// in its own database with its own credential, naming only the caller by
// default; the wait reads APPROVED once the person signed, and RUNNING only
// when the engine serves it; removing it ends it. Nothing in it approves.
func TestRequestPluginAgainstGuard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newKeptFixture(t, []string{"bot", "helper"})
	p := &pluginRequests{uids: map[string]uint32{"bot": keptPerson, "helper": keptPerson}}
	p.kept.Store(f.s)

	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(ctx, files)
	require.NoError(t, err)
	open := agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Executables: exec}

	// Not the caller among the agents: refused before the upload is taken.
	_, err = p.OpenPlugin(ctx, "bot", agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"helper"}, Executables: exec})
	var r *agent.PluginRefusal
	require.ErrorAs(t, err, &r)
	require.Equal(t, agent.ReasonPluginAgentNotAllowed, r.Reason)

	opened, err := p.OpenPlugin(ctx, "bot", open)
	require.NoError(t, err)
	require.Equal(t, []string{"bot"}, opened.Agents, "the caller alone by default, never every agent")
	b, err := approval.ParsePluginBinding(opened.BindingText)
	require.NoError(t, err)
	require.Equal(t, f.roles["bot"].Role, b.RequestedBy, "opened with the caller's own credential")
	require.Equal(t, []string{f.roles["bot"].Role}, b.Agents)
	require.Equal(t, []string{"bot"}, f.entries()[0].Agents, "the entry serves the caller alone")

	// The upload is used: the same id again is gone.
	_, err = p.OpenPlugin(ctx, "bot", open)
	var ae *agent.ArgumentError
	require.ErrorAs(t, err, &ae)

	st, err := p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStatePending, st.State)
	_, err = p.PluginApproval(ctx, "bot", uuid.Must(uuid.NewV7()))
	require.ErrorIs(t, err, agent.ErrPluginNotFound)

	// The person signs; nothing serves it here, so the wait reads APPROVED,
	// not RUNNING.
	f.sign(person.PluginOpenedApproval{ApprovalID: &opened.ApprovalID, BindingText: opened.BindingText})
	st, err = p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStateApproved, st.State)

	require.NoError(t, p.RemovePlugin(ctx, "bot", "acme-ner", "default"))
	require.Empty(t, f.entries())
	_, err = p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.ErrorIs(t, err, agent.ErrPluginNotFound)
	require.ErrorIs(t, p.RemovePlugin(ctx, "bot", "acme-ner", "default"), agent.ErrPluginNotFound)
}
