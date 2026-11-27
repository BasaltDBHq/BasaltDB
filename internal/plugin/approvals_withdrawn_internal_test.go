package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// An entry whose newest approval its agent withdrew is withheld with its
// own problem, PLUGIN_APPROVAL_WITHDRAWN, not as one waiting for the
// person: its link takes no signature. It is an approval reason, so an
// entry the ledger records as served gets its PLUGIN_DISABLED.
func TestWithdrawnApprovalHasItsOwnProblem(t *testing.T) {
	t.Parallel()
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "client_x"}
	check := func(status guardmodel.PluginApprovalStatus) withheldWhy {
		a := agentApprovals{read: true, newest: map[pluginmodel.EntryKey]guardmodel.PluginApprovalRecord{k: {
			ApprovalID: uuid.Must(uuid.NewV7()), Name: k.Name, Instance: k.Instance, Status: status,
			ExpiresAt: time.Now().Add(time.Hour), NamesCaller: true,
		}}}
		why, served := a.check(context.Background(), k, guardmodel.PluginDetail{}, guardmodel.PluginSettings{})
		require.False(t, served, status)
		return why
	}
	why := check(guardmodel.PluginApprovalStatusWithdrawn)
	require.Equal(t, problemPluginApprovalWithdrawn, why.code)
	require.Equal(t, whyApprovalWithdrawn, why.why)
	require.True(t, approvalReason(why.code))
	require.Equal(t, problemPluginAwaitingApproval, check(guardmodel.PluginApprovalStatusPending).code, "a pending one still waits")
}
