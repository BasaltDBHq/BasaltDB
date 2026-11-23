// Package pluginpage serves the plugin approval page's API (CONTRACT.md,
// Local pages): the request and the signed approval, on the page server's
// agents. app mounts its handlers on the page server.
package pluginpage

import (
	"context"
	"net/http"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// The plugin approval routes (CONTRACT.md, Local pages): the same link
// secret, origin, content type and size checks as the approval routes. The
// relay decides nothing: submit_plugin_approval verifies the signature.

// pluginPage serves the plugin approval page's API on the server's agents.
type pluginPage struct{ s *pageserver.Server }

// NewPluginHandlers are the plugin approval routes' handlers on s's
// agents, for s.MountPlugins.
func NewPluginHandlers(s *pageserver.Server) pageserver.PluginHandlers {
	p := pluginPage{s: s}
	return pageserver.PluginHandlers{Get: p.getPlugin, Approve: p.postPlugin}
}

// pluginApprovedDTO is the relay's answer for a plugin approval: no
// receipt.
type pluginApprovedDTO struct {
	ApprovalID string    `json:"approvalId"`
	Status     string    `json:"status"`
	ApprovedAt time.Time `json:"approvedAt"`
}

// asPlugins asks an agent's plugin approvals; an agent that serves none
// answers as one that does not know the id.
func asPlugins[T any](ask func(context.Context, pageserver.PluginApprovals) (T, error)) func(context.Context, pageserver.Agent) (T, error) {
	return func(ctx context.Context, a pageserver.Agent) (T, error) {
		p, ok := a.(pageserver.PluginApprovals)
		if !ok {
			var zero T
			return zero, agent.ErrNotThisAgent
		}
		return ask(ctx, p)
	}
}

func (p pluginPage) getPlugin(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.ApprovalParam)
	if !ok {
		return
	}
	req, err := pageserver.Find(r.Context(), p.s, asPlugins(func(ctx context.Context, pa pageserver.PluginApprovals) (approval.PluginRequest, error) {
		return pa.PluginApprovalRequest(ctx, id)
	}))
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, req)
}

func (p pluginPage) postPlugin(w http.ResponseWriter, r *http.Request) {
	id, ok := p.s.LinkedID(w, r, pageserver.ApprovalParam)
	if !ok {
		return
	}
	body, ok := p.s.Body(w, r)
	if !ok {
		return
	}
	resp, err := approval.DecodePluginResponse(body)
	if err != nil || resp.ApprovalID != id {
		p.s.Fail(w, &toolresult.ToolError{Code: guidance.CodeInvalidArgument, Message: "the body is not this plugin approval's signed response"})
		return
	}
	at, err := pageserver.Find(r.Context(), p.s, asPlugins(func(ctx context.Context, pa pageserver.PluginApprovals) (time.Time, error) {
		return pa.RelayPluginApproval(ctx, resp)
	}))
	if err != nil {
		p.s.Fail(w, err)
		return
	}
	p.s.Reply(w, pluginApprovedDTO{ApprovalID: id.String(), Status: "APPROVED", ApprovedAt: at.UTC()})
}
