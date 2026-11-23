package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

// PluginApprovalRequest is the request of a pending plugin approval this
// agent's role opened: its binding and settings texts as Postgres built
// them, and the database's passkeys.
func (s *Service) PluginApprovalRequest(ctx context.Context, id uuid.UUID) (approval.PluginRequest, error) {
	return s.plugin.PluginApprovalRequest(ctx, id)
}

// RelayPluginApproval relays the person's signature of a plugin approval
// this agent's role opened to submit_plugin_approval, and returns when
// Postgres recorded it.
func (s *Service) RelayPluginApproval(ctx context.Context, r approval.PluginApprovalResponse) (time.Time, error) {
	return s.plugin.RelayPluginApproval(ctx, r)
}

// RequestPlugin serves request_plugin: it prepares a plugin install or
// change for the person to approve, waits once for it, or removes a plugin.
// meta is the request's _meta object, nil when it had none.
func (s *Service) RequestPlugin(ctx context.Context, source, name, instance string, agents []string, remove *bool, approvalID string, waitForApproval *int, meta json.RawMessage) (any, error) {
	return s.plugin.RequestPlugin(ctx, source, name, instance, agents, remove, approvalID, waitForApproval, meta)
}

// PluginUploadsServed reports why this engine does not serve the plugin
// uploads, nil when it does.
func (s *Service) PluginUploadsServed() error { return s.plugin.PluginUploadsServed() }
