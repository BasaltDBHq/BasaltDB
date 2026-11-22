package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// What the plugin approval routes of the local pages ask of an agent
// (CONTRACT.md, Local pages): the request of a plugin approval this
// agent's role opened and the relay of the person's signature; the short
// link comes with request_plugin's result. The relay decides nothing:
// submit_plugin_approval verifies the passkey signature in Postgres.

// PluginApprovalStore is the guard's plugin approvals on the agent's own
// credential (schema version guard.PluginApprovalsVersion).
type PluginApprovalStore interface {
	// ReadPluginApproval is one plugin approval the role may see, and false
	// when there is none. Its texts are set only for the role that opened
	// it.
	ReadPluginApproval(ctx context.Context, id uuid.UUID) (guard.PluginApprovalRecord, bool, error)
	// SubmitPluginApproval relays the person's assertion; Postgres verifies
	// it and records the approval.
	SubmitPluginApproval(ctx context.Context, r guard.PluginApprovalResponse) (time.Time, error)
}

// PluginApprovalRequest is the request of a pending plugin approval this
// agent's role opened: its binding and settings texts as Postgres built
// them, and the database's passkeys.
func (s *Service) PluginApprovalRequest(ctx context.Context, id uuid.UUID) (approval.PluginRequest, error) {
	r, err := s.openPluginApproval(ctx, id)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	return approval.PluginRequest{ApprovalID: r.ApprovalID, Binding: r.BindingText, Settings: r.SettingsText, CredentialIDs: ids}, nil
}

// RelayPluginApproval relays the person's signature of a plugin approval
// this agent's role opened to submit_plugin_approval, and returns when
// Postgres recorded it.
func (s *Service) RelayPluginApproval(ctx context.Context, r approval.PluginApprovalResponse) (time.Time, error) {
	if _, err := s.openPluginApproval(ctx, r.ApprovalID); err != nil {
		return time.Time{}, err
	}
	at, err := s.PluginApprovals.SubmitPluginApproval(ctx, guard.PluginApprovalResponse{ApprovalID: r.ApprovalID, Assertion: r.Assertion()})
	if err != nil {
		return time.Time{}, s.pluginRelayError(ctx, r.ApprovalID, err)
	}
	return at, nil
}

// openPluginApproval is a plugin approval this agent's role opened that can
// still be signed. Every other case is ErrNotThisAgent, before anything
// about the approval is told: no plugin approval store, a guard older than
// schema version 5 (which cannot hold one), an approval the role cannot
// see or only sees as a named agent (no binding text, so the opener is
// asked instead), and a proof that does not match the binding text.
func (s *Service) openPluginApproval(ctx context.Context, id uuid.UUID) (guard.PluginApprovalRecord, error) {
	if s.PluginApprovals == nil {
		return guard.PluginApprovalRecord{}, ErrNotThisAgent
	}
	if err := s.Admit(ctx); err != nil {
		return guard.PluginApprovalRecord{}, err
	}
	st, err := s.Probe.GuardStatus(ctx)
	if err != nil {
		return guard.PluginApprovalRecord{}, err
	}
	if !holdsPluginApprovals(st) {
		return guard.PluginApprovalRecord{}, ErrNotThisAgent
	}
	r, ok, err := s.PluginApprovals.ReadPluginApproval(ctx, id)
	if err != nil {
		return guard.PluginApprovalRecord{}, err
	}
	if !ok || r.BindingText == "" {
		return guard.PluginApprovalRecord{}, ErrNotThisAgent
	}
	switch {
	case r.Status == guard.PluginApprovalStatusExpired || (r.Status == guard.PluginApprovalStatusPending && !s.Now().Before(r.ExpiresAt)):
		return r, pluginExpired(r.ApprovalID, r.ExpiresAt)
	case r.Status == guard.PluginApprovalStatusApproved:
		return r, pluginAlreadyApproved(r.ApprovalID)
	case r.Status == guard.PluginApprovalStatusCancelled:
		return r, pluginCancelled(r.ApprovalID)
	case r.Status != guard.PluginApprovalStatusPending:
		return r, ErrNotThisAgent
	}
	return r, nil
}

// holdsPluginApprovals reports whether a guard has plugin approvals: schema
// version guard.PluginApprovalsVersion is installed.
func holdsPluginApprovals(st guard.Status) bool {
	return st.Installed >= guard.PluginApprovalsVersion &&
		!slices.Contains(st.MissingBreaking, guard.PluginApprovalsVersion) &&
		!slices.Contains(st.MissingNonBreaking, guard.PluginApprovalsVersion)
}

// The plugin page's answers. They are the page's own (PageError), never
// the held-write guidance of the agent's catalog: a person reads them on
// the plugin approval page.

func pluginPageError(code, reason, message, person string, steps []mcp.NextStep) error {
	return &PageError{ToolError: &mcp.ToolError{Code: code, Reason: reason, Message: message, PersonMessage: person, NextSteps: steps}}
}

// askAgentForLink is the person's step when the page can do nothing more.
func askAgentForLink() []mcp.NextStep {
	steps, err := NewSteps().TellAgent("Ask the agent for a new link.").Build()
	if err != nil {
		return nil
	}
	return steps
}

func pluginExpired(id uuid.UUID, at time.Time) error {
	when := at.UTC().Format(personTime)
	return pluginPageError(CodeApprovalExpired, "",
		fmt.Sprintf("plugin approval %s expired at %s; nothing was approved", id, when),
		fmt.Sprintf("This plugin approval expired at %s. Nothing was approved; ask the agent for a new link.", when),
		askAgentForLink())
}

func pluginAlreadyApproved(id uuid.UUID) error {
	return pluginPageError(CodeApprovalInvalid, reasonAlreadyUsed,
		fmt.Sprintf("plugin approval %s is already signed", id),
		"This plugin approval is already signed. The plugin starts within a few seconds of the signature.", nil)
}

func pluginCancelled(id uuid.UUID) error {
	return pluginPageError(CodeApprovalInvalid, "",
		fmt.Sprintf("plugin approval %s was cancelled: a newer approval for the same plugin replaced it", id),
		"A newer approval for this plugin replaced this one, so nothing here can be approved. Ask the agent for the newest link.",
		askAgentForLink())
}

// pluginRelayError is the page's answer when Postgres refused the person's
// signature of plugin approval id: told apart by the guard's detail, the
// message carrying it. Any other failure (the database cannot be reached)
// is returned as it is, for the usual mapping.
func (s *Service) pluginRelayError(ctx context.Context, id uuid.UUID, err error) error {
	code, ok := ledgerCode(err)
	if !ok {
		return err
	}
	detail := storeDetail(err)
	msg := ToolError(err).Message
	switch {
	case code == guard.CodeApprovalExpired:
		r, found, readErr := s.PluginApprovals.ReadPluginApproval(ctx, id)
		if readErr == nil && found {
			return pluginExpired(id, r.ExpiresAt)
		}
		return pluginPageError(CodeApprovalExpired, "", msg,
			"This plugin approval expired. Nothing was approved; ask the agent for a new link.", askAgentForLink())
	case code != guard.CodeApprovalInvalid:
		return err
	case detail == guard.DetailAlreadyApproved:
		return pluginAlreadyApproved(id)
	case detail == guard.DetailApprovalCancelled:
		return pluginCancelled(id)
	case detail == guard.DetailApprovalNotFound:
		return ErrNotThisAgent
	}
	te := ToolError(err)
	if te.Reason == reasonPasskeyRevoked {
		steps, stepErr := NewSteps().
			RunCommand(s.Commands.PasskeyList(), "See which passkeys this database accepts.").
			RunCommand(s.Commands.Init("--add-passkey"), "Register your passkey with this command: it adds the one you use and changes nothing else.").
			Build()
		if stepErr != nil {
			return errors.Join(err, stepErr)
		}
		return pluginPageError(CodeApprovalInvalid, reasonPasskeyRevoked, msg,
			"The plugin approval was signed with a passkey this database does not accept (unknown or revoked), so nothing was "+
				"approved. Check your passkeys, register one if needed, then try again on this page.", steps)
	}
	return pluginPageError(CodeApprovalInvalid, reasonBadSignature, msg,
		"The plugin approval code did not verify, so nothing was approved. Approve again on this page.", nil)
}
