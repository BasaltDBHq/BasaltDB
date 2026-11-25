package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// What the plugin approval routes of the local pages ask of an agent
// (CONTRACT.md, Local pages): the request of a plugin approval this
// agent's role opened and the relay of the person's signature; the short
// link comes with request_plugin's result. The relay decides nothing:
// submit_plugin_approval verifies the passkey signature in Postgres.

// PluginApprovalStore is the guard's plugin approvals on the agent's own
// credential (schema version Plugin.ApprovalsVersion).
type PluginApprovalStore interface {
	// ReadPluginApproval is one plugin approval the role may see, and false
	// when there is none. Its texts are set only for the role that opened
	// it.
	ReadPluginApproval(ctx context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error)
	// SubmitPluginApproval relays the person's assertion; Postgres verifies
	// it and records the approval.
	SubmitPluginApproval(ctx context.Context, r guardmodel.PluginApprovalResponse) (time.Time, error)
}

// PluginApprovalRequest is the request of a pending plugin approval this
// agent's role opened: its binding and settings texts as Postgres built
// them, and the database's passkeys.
func (pc *Service) PluginApprovalRequest(ctx context.Context, id uuid.UUID) (approval.PluginRequest, error) {
	r, err := pc.openPluginApproval(ctx, id)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	ids, err := pc.delivery.CredentialIDs(ctx)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	// The engine relays only texts that follow the text rules.
	if err := approval.CheckTexts(r.BindingText, r.SettingsText); err != nil {
		return approval.PluginRequest{}, err
	}
	return approval.PluginRequest{ApprovalID: r.ApprovalID, Binding: r.BindingText, Settings: r.SettingsText, CredentialIDs: ids}, nil
}

// RelayPluginApproval relays the person's signature of a plugin approval
// this agent's role opened to submit_plugin_approval, and returns when
// Postgres recorded it.
func (pc *Service) RelayPluginApproval(ctx context.Context, r approval.PluginApprovalResponse) (time.Time, error) {
	if _, err := pc.openPluginApproval(ctx, r.ApprovalID); err != nil {
		return time.Time{}, err
	}
	at, err := pc.deps.Approvals.SubmitPluginApproval(ctx, guardmodel.PluginApprovalResponse{ApprovalID: r.ApprovalID, Assertion: r.Assertion()})
	if err != nil {
		return time.Time{}, pc.pluginRelayError(ctx, r.ApprovalID, err)
	}
	return at, nil
}

// openPluginApproval is a plugin approval this agent's role opened that can
// still be signed. Every other case is ErrNotThisAgent, before anything
// about the approval is told: no plugin approval store, a guard older than
// schema version 5 (which cannot hold one), an approval the role cannot
// see or only sees as a named agent (no binding text, so the opener is
// asked instead), and a proof that does not match the binding text.
func (pc *Service) openPluginApproval(ctx context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, error) {
	if pc.deps.Approvals == nil {
		return guardmodel.PluginApprovalRecord{}, linksvc.ErrNotThisAgent
	}
	if err := pc.admit.Admit(ctx); err != nil {
		return guardmodel.PluginApprovalRecord{}, err
	}
	st, err := pc.status.GuardStatus(ctx)
	if err != nil {
		return guardmodel.PluginApprovalRecord{}, err
	}
	if !holdsPluginApprovals(st, pc.deps.ApprovalsVersion) {
		return guardmodel.PluginApprovalRecord{}, linksvc.ErrNotThisAgent
	}
	r, ok, err := pc.deps.Approvals.ReadPluginApproval(ctx, id)
	if err != nil {
		return guardmodel.PluginApprovalRecord{}, err
	}
	if !ok || r.BindingText == "" {
		return guardmodel.PluginApprovalRecord{}, linksvc.ErrNotThisAgent
	}
	switch {
	case r.Status == guardmodel.PluginApprovalStatusExpired || (r.Status == guardmodel.PluginApprovalStatusPending && !pc.core.Now().Before(r.ExpiresAt)):
		return r, pluginExpired(r.ApprovalID, r.ExpiresAt)
	case r.Status == guardmodel.PluginApprovalStatusApproved:
		return r, pluginAlreadyApproved(r.ApprovalID)
	case r.Status == guardmodel.PluginApprovalStatusCancelled:
		return r, pluginCancelled(r.ApprovalID)
	case r.Status != guardmodel.PluginApprovalStatusPending:
		return r, linksvc.ErrNotThisAgent
	}
	return r, nil
}

// The plugin page's answers. They are the page's own (PageError), never
// the held-write guidance of the agent's catalog: a person reads them on
// the plugin approval page.

func pluginPageError(code, reason, message, person string, steps []toolresult.NextStep) error {
	return &guidance.PageError{ToolError: &toolresult.ToolError{Code: code, Reason: reason, Message: message, PersonMessage: person, NextSteps: steps}}
}

// askAgentForLink is the person's step when the page can do nothing more.
func askAgentForLink() []toolresult.NextStep {
	steps, err := guidance.NewSteps().TellAgent("Ask the agent for a new link.").Build()
	if err != nil {
		return nil
	}
	return steps
}

func pluginExpired(id uuid.UUID, at time.Time) error {
	when := at.UTC().Format(guidance.PersonTime)
	return pluginPageError(guidance.CodeApprovalExpired, "",
		fmt.Sprintf("plugin approval %s expired at %s; nothing was approved", id, when),
		fmt.Sprintf("This plugin approval expired at %s. Nothing was approved; ask the agent for a new link.", when),
		askAgentForLink())
}

func pluginAlreadyApproved(id uuid.UUID) error {
	return pluginPageError(guidance.CodeApprovalInvalid, guidance.ReasonAlreadyUsed,
		fmt.Sprintf("plugin approval %s is already signed", id),
		"This plugin approval is already signed. The plugin starts within a few seconds of the signature.", nil)
}

func pluginCancelled(id uuid.UUID) error {
	return pluginPageError(guidance.CodeApprovalInvalid, "",
		fmt.Sprintf("plugin approval %s was cancelled: a newer approval for the same plugin replaced it", id),
		"A newer approval for this plugin replaced this one, so nothing here can be approved. Ask the agent for the newest link.",
		askAgentForLink())
}

// pluginRelayError is the page's answer when Postgres refused the person's
// signature of plugin approval id: told apart by the guard's detail, the
// message carrying it. Any other failure (the database cannot be reached)
// is returned as it is, for the usual mapping.
func (pc *Service) pluginRelayError(ctx context.Context, id uuid.UUID, err error) error {
	code, ok := guidance.LedgerCode(err)
	if !ok {
		return err
	}
	detail := guidance.StoreDetail(err)
	msg := pc.core.Errors.ToolError(err).Message
	switch {
	case code == guardmodel.CodeApprovalExpired:
		r, found, readErr := pc.deps.Approvals.ReadPluginApproval(ctx, id)
		if readErr == nil && found {
			return pluginExpired(id, r.ExpiresAt)
		}
		return pluginPageError(guidance.CodeApprovalExpired, "", msg,
			"This plugin approval expired. Nothing was approved; ask the agent for a new link.", askAgentForLink())
	case code != guardmodel.CodeApprovalInvalid:
		return err
	case detail == guardmodel.DetailAlreadyApproved:
		return pluginAlreadyApproved(id)
	case detail == guardmodel.DetailApprovalCancelled:
		return pluginCancelled(id)
	case detail == guardmodel.DetailApprovalNotFound:
		return linksvc.ErrNotThisAgent
	}
	te := pc.core.Errors.ToolError(err)
	if te.Reason == guidance.ReasonPasskeyRevoked {
		steps, stepErr := guidance.NewSteps().
			TellAgent(guidance.AskAgentForRegisterLinkText).
			Build()
		if stepErr != nil {
			return errors.Join(err, stepErr)
		}
		return pluginPageError(guidance.CodeApprovalInvalid, guidance.ReasonPasskeyRevoked, msg,
			"The plugin approval was signed with a passkey this database does not accept (unknown or revoked), so nothing was "+
				"approved. Ask the agent for a link to register the passkey you use, then try again on this page.", steps)
	}
	return pluginPageError(guidance.CodeApprovalInvalid, guidance.ReasonBadSignature, msg,
		"The plugin approval code did not verify, so nothing was approved. Approve again on this page.", nil)
}
