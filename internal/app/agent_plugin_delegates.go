package app

import (
	"context"
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

// PluginUploadsServed reports why this engine does not serve the plugin
// uploads, nil when it does.
func (s *Service) PluginUploadsServed() error { return s.plugin.PluginUploadsServed() }
