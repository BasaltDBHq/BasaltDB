package store

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// submit_plugin_approval's answers map to the plugin's typed refusals the
// way the plugin approval page told them apart: APPROVAL_EXPIRED, the
// guard's APPROVAL_INVALID details compared for equality, a revoked or
// unknown passkey, and any other APPROVAL_INVALID a bad signature. Any other
// answer is returned as MapError made it, and a refusal keeps the mapped
// error in its chain, so the page's message reads as before.
func TestPluginApprovalRefusals(t *testing.T) {
	t.Parallel()
	expired := guardErr("BS005", "APPROVAL_EXPIRED", "plugin approval expired", "")
	rows := []struct {
		name   string
		err    error
		reason pluginmodel.ApprovalReason
	}{
		{"expired", expired, pluginmodel.ApprovalExpired},
		{"already approved", approvalInvalid(guard.DetailAlreadyApproved), pluginmodel.ApprovalAlreadyApproved},
		{"cancelled", approvalInvalid(guard.DetailApprovalCancelled), pluginmodel.ApprovalCancelled},
		{"not found", approvalInvalid(guard.DetailApprovalNotFound), pluginmodel.ApprovalNotFound},
		{"unknown passkey", approvalInvalid("unknown passkey"), pluginmodel.ApprovalPasskeyRevoked},
		{"bad signature", approvalInvalid("signature does not verify"), pluginmodel.ApprovalBadSignature},
		{"contains a detail", approvalInvalid("NOT_FOUND here"), pluginmodel.ApprovalBadSignature},
		{"not allowed", guardErr("BS007", "NOT_ALLOWED", guard.DetailUnknownAgent, ""), ""},
		{"permission denied", guardErr("42501", "permission denied", "", ""), ""},
		{"not a store error", errors.New("conn closed"), ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			mapped := MapError(row.err)
			out := pluginApprovalRefusal(mapped)
			refused := pluginmodel.ApprovalRefusalOf(out)
			if row.reason == "" {
				require.Nil(t, refused, "%v", out)
				require.Equal(t, mapped, out, "returned as MapError made it")
				return
			}
			require.NotNil(t, refused, "%v", out)
			require.Equal(t, row.reason, refused.Reason)
			require.Same(t, mapped, refused.Err, "wraps the mapped error")
			require.Equal(t, mapped.Error(), out.Error(), "keeps the store's text")
			var se *action.StoreError
			require.ErrorAs(t, out, &se)
		})
	}
}
