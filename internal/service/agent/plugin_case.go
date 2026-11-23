package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// pluginCase is the plugin use case: request_plugin and the plugin approval
// pages. It holds a reference to the shared core group and to its own
// PluginDeps. What it needs from the delivery and status use cases it names as
// small ports of its own.
type pluginCase struct {
	core     *CoreDeps
	deps     *PluginDeps
	delivery pluginDelivery
	status   pluginStatusView
	admit    admitter
}

// pluginDelivery is what the plugin use case asks of the delivery use case.
type pluginDelivery interface {
	CredentialIDs(ctx context.Context) ([]passkey.Bytes, error)
	IssuedLink(page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) (string, error)
	RelayLink(ctx context.Context, page func(string, uuid.UUID) string, id uuid.UUID, expires time.Time) string
	RelayConnected() bool
	PollInterval() time.Duration
}

// pluginStatusView is what the plugin use case reads of the status use case.
type pluginStatusView interface {
	// sameUser says the engine runs as the person's own OS user.
	sameUser() bool
	// devLocalPages says engine.json has devLocalPages set.
	devLocalPages() bool
	// vaultState is the engine's Vault state, vaultStateOff when there is
	// no Vault reporter.
	vaultState() string
	// guardStatus reads the guard's state on the agent's credential.
	guardStatus(ctx context.Context) (guardmodel.Status, error)
}

func newPluginCase(core *CoreDeps, deps *PluginDeps, delivery pluginDelivery, status pluginStatusView, admit admitter) *pluginCase {
	return &pluginCase{core: core, deps: deps, delivery: delivery, status: status, admit: admit}
}

// PluginApprovalRequest is the request of a pending plugin approval this
// agent's role opened: its binding and settings texts as Postgres built
// them, and the database's passkeys.
// PluginApprovalRequest is the plugin use case's PluginApprovalRequest.
func (s *Service) PluginApprovalRequest(ctx context.Context, id uuid.UUID) (approval.PluginRequest, error) {
	return s.plugin.PluginApprovalRequest(ctx, id)
}

// RelayPluginApproval relays the person's signature of a plugin approval
// this agent's role opened to submit_plugin_approval, and returns when
// Postgres recorded it.
// RelayPluginApproval is the plugin use case's RelayPluginApproval.
func (s *Service) RelayPluginApproval(ctx context.Context, r approval.PluginApprovalResponse) (time.Time, error) {
	return s.plugin.RelayPluginApproval(ctx, r)
}

// RequestPlugin serves request_plugin. meta is the call's _meta, which
// carries basalt mcp's upload for source.
// RequestPlugin is the plugin use case's RequestPlugin.
func (s *Service) RequestPlugin(ctx context.Context, a requestPluginArgs, meta json.RawMessage) (requestPluginResult, error) {
	return s.plugin.RequestPlugin(ctx, a, meta)
}

// PluginUploadsServed reports why this engine does not serve the plugin
// uploads, nil when it does.
func (s *Service) PluginUploadsServed() error { return s.plugin.PluginUploadsServed() }
