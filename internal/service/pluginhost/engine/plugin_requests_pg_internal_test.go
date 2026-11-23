//go:build unix

package engine

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/shim"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// request_plugin on a real guard: the caller's upload opens one approval
// in its own database with its own credential, naming only the caller by
// default; the wait reads APPROVED once the person signed, and RUNNING only
// when the engine serves it; removing it ends it. Nothing in it approves.
func TestRequestPluginAgainstGuard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newKeptFixture(t, []string{"bot", "helper"})
	p := &Requests{uids: map[string]uint32{"bot": keptPerson, "helper": keptPerson}, admitted: []uint32{keptPerson}}
	p.kept.Store(f.s)

	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(ctx, files)
	require.NoError(t, err)

	// Not the caller among the agents: refused, and the upload is dropped,
	// so a refused call holds none of the engine's few uploads.
	_, err = p.OpenPlugin(ctx, "bot", agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"helper"}, Executables: exec})
	var r *agent.PluginRefusedError
	require.ErrorAs(t, err, &r)
	require.Equal(t, agent.ReasonPluginAgentNotAllowed, r.Reason)
	_, err = p.OpenPlugin(ctx, "bot", agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Executables: exec})
	var gone *guidance.ArgumentError
	require.ErrorAs(t, err, &gone, "the refused call's upload is gone")

	// A refusal of PLUGIN_OPEN itself drops the upload too: one before it
	// took the upload (its scope check) and one after (the manifest).
	for _, kase := range []struct {
		reason string
		open   agent.PluginOpen
	}{
		{agent.ReasonPluginAgentNotAllowed, agent.PluginOpen{Name: "acme-ner", Instance: "default", Agents: []string{"bot", "ghost"}, Executables: exec}},
		{"BAD_MANIFEST", agent.PluginOpen{Name: "other-ner", Instance: "default", Executables: exec}},
	} {
		id, err = f.client.PluginUpload(ctx, files)
		require.NoError(t, err)
		kase.open.UploadID = &id
		_, err = p.OpenPlugin(ctx, "bot", kase.open)
		require.ErrorAs(t, err, &r)
		require.Equal(t, kase.reason, r.Reason)
		_, err = p.OpenPlugin(ctx, "bot", agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Executables: exec})
		require.ErrorAs(t, err, &gone, "the refused call's upload is gone (%s)", kase.reason)
	}

	// The agent's own refusals drop it through DropUpload.
	id, err = f.client.PluginUpload(ctx, files)
	require.NoError(t, err)
	p.DropUpload("bot", id)
	_, err = p.OpenPlugin(ctx, "bot", agent.PluginOpen{UploadID: &id, Name: "acme-ner", Instance: "default", Executables: exec})
	require.ErrorAs(t, err, &gone, "a dropped upload is gone")

	// The real folder through basalt mcp's uploader, as the agent's OS user.
	dir := t.TempDir()
	for _, f := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, f.Path)), 0o755))
		mode := os.FileMode(0o644)
		if slices.Contains(exec, f.Path) {
			mode = 0o755
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, f.Path), f.Data, mode))
	}
	up, err := shim.NewPluginUploader(serveAgentSocket(t, f.base, p, "bot", func() error { return nil }))(ctx, dir)
	require.NoError(t, err)
	require.Equal(t, "acme-ner", up.Name)
	require.Equal(t, exec, up.Executables)
	id = uuid.MustParse(up.UploadID)
	open := agent.PluginOpen{UploadID: &id, Name: up.Name, Instance: "default", Executables: up.Executables}

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
	var ae *guidance.ArgumentError
	require.ErrorAs(t, err, &ae)

	st, err := p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStatePending, st.State)
	_, err = p.PluginApproval(ctx, "bot", uuid.Must(uuid.NewV7()))
	require.ErrorIs(t, err, agent.ErrPluginNotFound)

	// The person signs; nothing serves it here, so the wait reads APPROVED,
	// not RUNNING.
	f.sign(plugin.PluginOpenedApproval{ApprovalID: &opened.ApprovalID, BindingText: opened.BindingText})
	st, err = p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.NoError(t, err)
	require.Equal(t, agent.PluginStateApproved, st.State)

	require.NoError(t, p.RemovePlugin(ctx, "bot", "acme-ner", "default"))
	require.Empty(t, f.entries())
	_, err = p.PluginApproval(ctx, "bot", opened.ApprovalID)
	require.ErrorIs(t, err, agent.ErrPluginNotFound)
	require.ErrorIs(t, p.RemovePlugin(ctx, "bot", "acme-ner", "default"), agent.ErrPluginNotFound)
}
