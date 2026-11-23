package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/laststop"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/updatecheck"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// The tests fill the host as the app does, with the real adapters.
func init() { UseHost(testHost()) }

func testHost() Host {
	return Host{
		StartCommand: osservice.StartCommand,
		RestartArgs:  osservice.RestartArgs,
		StartHoldOffUntil: func(stop LastStop, configPath string, now time.Time) (time.Time, bool) {
			return laststop.StartHoldOffUntil(laststop.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
		},
		CrashReports: func(dirs ...string) []CrashReport {
			reports := crash.List(dirs...)
			out := make([]CrashReport, 0, len(reports))
			for _, r := range reports {
				out = append(out, CrashReport{
					ID: r.ID, Time: r.Time, Version: r.Version, Command: r.Command,
					IssueURL: func(limit int) string { link, _, _ := r.IssueURLWithin(limit); return link },
				})
			}
			return out
		},
		VaultConflict:        vault.IsConflict,
		ErrVaultNotConnected: vault.ErrNotConnected,
		AfterAnswer:          vault.AfterAnswer,
		RotateSession:        vault.RotateSession,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
		ErrRevertNotFound:      ledger.ErrRevertNotFound,
		ErrApprovalNotFound:    ledger.ErrApprovalNotFound,
		ErrInvalidParams:       ledger.ErrInvalidParams,
		ErrInvalidIntent:       guard.ErrInvalidIntent,
		ApprovalSortSpec:       ledger.ApprovalSortSpec,
		Record:                 func(ch action.Change, rows []action.RowChange) any { return ledger.RecordFromDomain(ch, rows) },
		PluginApprovalsVersion: guard.PluginApprovalsVersion,
		LatestGuardVersion:     guard.LatestVersion,
		UpdateMessage: func(n UpdateNotice, exe string) string {
			return updatecheck.Notice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}.AgentMessage(exe)
		},
	}
}

// The agent keeps its own copies of a few strings the adapters define; they
// must not drift.
func TestHostCopiesMatchTheAdapters(t *testing.T) {
	t.Parallel()
	require.Equal(t, ledger.ApprovalPending, approvalPending)
	require.Equal(t, ledger.ApprovalApproved, approvalApproved)
	require.Equal(t, ledger.ApprovalApplied, approvalApplied)
	require.Equal(t, ledger.ApprovalExpired, approvalExpired)
	require.Equal(t, ledger.RevertPending, revertPending)
	require.Equal(t, ledger.RevertApplying, revertApplying)
	require.Equal(t, ledger.RevertApplied, revertApplied)
	require.Equal(t, ledger.RevertRejected, revertRejected)
	require.Equal(t, ledger.RevertExpired, revertExpired)
	require.Equal(t, string(vault.StateOff), vaultStateOff)
	require.Equal(t, string(vault.StateConnected), vaultStateConnected)
	require.Equal(t, string(vault.StateKeyError), vaultStateKeyError)
	require.Equal(t, mcp.MetaPluginUpload, MetaPluginUpload)
	require.Equal(t, mcp.PluginUpload(PluginUpload{UploadID: "a"}).UploadID, "a", "the same fields as the protocol's")
}

// An error value the host left nil is a wiring defect, not "not this error":
// sentinel panics rather than answer false.
func TestSentinelPanicsOnUnsetTarget(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { sentinel(errors.New("x"), nil) })
	require.Panics(t, func() { sentinel(nil, nil) })
	require.True(t, sentinel(ledger.ErrRevertNotFound, ledger.ErrRevertNotFound))
	require.False(t, sentinel(errors.New("x"), ledger.ErrRevertNotFound))
}
