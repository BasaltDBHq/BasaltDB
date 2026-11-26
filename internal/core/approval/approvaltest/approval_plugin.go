package approvaltest

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
)

// pluginSettings is how many texts a plugin approval link carries after the
// binding: the settings.
const pluginSettings = 1

// ParsePluginRequest decodes a plugin approval link fragment, with or
// without '#', and checks it (Check).
func ParsePluginRequest(fragment string) (approval.PluginRequest, approval.PluginBinding, error) {
	r, err := linkcodec.DecodeRequest(fragment, pluginSettings, func(binding string, lines []string, ids []passkey.Bytes) approval.PluginRequest {
		out := approval.PluginRequest{Binding: binding, Settings: lines[0], CredentialIDs: ids}
		if b, err := approval.ParsePluginBinding(binding); err == nil {
			out.ApprovalID = b.ApprovalID
		}
		return out
	})
	if err != nil {
		return approval.PluginRequest{}, approval.PluginBinding{}, approval.Invalid("plugin approval request %v", err)
	}
	b, err := r.Check()
	if err != nil {
		return approval.PluginRequest{}, approval.PluginBinding{}, err
	}
	return r, b, nil
}

// NewPluginResponse wraps an assertion for approvalID.
func NewPluginResponse(approvalID uuid.UUID, a passkey.Assertion) approval.PluginApprovalResponse {
	return approval.PluginApprovalResponse{ApprovalID: approvalID, SignedAssertion: passkeytest.Signed(a)}
}

// VerifyPlugin checks a response against the binding text it should sign
// and the stored passkey, the way submit_plugin_approval does (without the
// approval's state and expiry, which only Postgres knows). It returns the
// new signature counter.
func VerifyPlugin(bindingText string, cred passkey.Credential, r approval.PluginApprovalResponse) (uint32, error) {
	b, err := approval.ParsePluginBinding(bindingText)
	if err != nil {
		return 0, err
	}
	if b.ApprovalID != r.ApprovalID {
		return 0, approval.Invalid("response is for plugin approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	count, err := passkey.VerifyAssertion(cred, passkeytest.Challenge(bindingText), r.Assertion())
	if err != nil {
		return 0, fmt.Errorf("plugin approval %s: %w", r.ApprovalID, err)
	}
	return count, nil
}
