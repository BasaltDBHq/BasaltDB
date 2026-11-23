package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/status/out/updatecheck"
)

// testDeps are the dependencies the tests take from the adapters, filled as
// the app does, with the real adapters. A test sets the rest.
func testDeps() Deps {
	var d Deps
	d.Core.ServiceManager = testManager()
	d.Core.Errors = testErrors()
	d.Write.Record = func(ch action.Change, rows []action.RowChange) any { return ledger.RecordFromDomain(ch, rows) }
	d.Approval.ErrNotFound = ledger.ErrApprovalNotFound
	d.Approval.SortSpec = ledger.ApprovalSortSpec
	d.Revert.ErrNotFound = ledger.ErrRevertNotFound
	d.Revert.AfterAnswer = vault.AfterAnswer
	d.Revert.RotateSession = vault.RotateSession
	d.Delivery.VaultConflict = vault.IsConflict
	d.Delivery.ErrVaultNotConnected = vault.ErrNotConnected
	d.Status.CrashReports = func(dirs ...string) []CrashReport {
		reports := crash.List(dirs...)
		out := make([]CrashReport, 0, len(reports))
		for _, r := range reports {
			out = append(out, CrashReport{
				ID: r.ID, Time: r.Time, Version: r.Version, Command: r.Command,
				IssueURL: func(limit int) string { link, _, _ := r.IssueURLWithin(limit); return link },
			})
		}
		return out
	}
	d.Status.LatestGuardVersion = guard.LatestVersion
	d.Status.UpdateMessage = func(n UpdateNotice, exe string) string {
		return updatecheck.Notice{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL}.AgentMessage(exe)
	}
	d.Status.StartHoldOffUntil = testEngineHost().StartHoldOffUntil
	d.Plugin.ApprovalsVersion = guard.PluginApprovalsVersion
	return d
}

// useStore binds every port of d that reads the agent's store to s.
func useStore(d *Deps, s SQLStore) {
	d.Core.Store, d.Write.Store, d.Approval.Store, d.Revert.Store, d.Status.Passkeys = s, s, s, s, s
}

func testManager() ServiceManager {
	return ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}

func testErrors() ErrorMap {
	return ErrorMap{
		InvalidParams: ledger.ErrInvalidParams,
		InvalidIntent: guard.ErrInvalidIntent,
		RowTooLarge: func(err error) (string, bool) {
			var rl *resultsize.RowTooLargeError
			if errors.As(err, &rl) {
				return rl.Error(), true
			}
			return "", false
		},
	}
}

func testEngineHost() EngineHost {
	return EngineHost{
		LatestGuardVersion: guard.LatestVersion,
		StartHoldOffUntil: func(stop LastStop, configPath string, now time.Time) (time.Time, bool) {
			return laststop.StartHoldOffUntil(laststop.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
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

// Every port the app used to hand the agent as one Host is a required
// dependency now: an empty Deps is refused naming each of them, so a port the
// app forgets stops the engine at start, not at its first use.
func TestNewServiceRequiresEveryAdapterPort(t *testing.T) {
	t.Parallel()
	missing := Deps{}.missing()
	for _, name := range []string{
		"Core.ServiceManager", "Core.Errors.InvalidParams", "Core.Errors.InvalidIntent", "Core.Errors.RowTooLarge",
		"Write.Record", "Approval.ErrNotFound", "Revert.ErrNotFound", "Revert.AfterAnswer", "Revert.RotateSession",
		"Delivery.VaultConflict", "Delivery.ErrVaultNotConnected", "Status.CrashReports",
		"Status.LatestGuardVersion", "Status.UpdateMessage", "Status.StartHoldOffUntil",
	} {
		require.Contains(t, missing, name)
	}
	require.PanicsWithValue(t, "agent: required dependencies missing: "+strings.Join(missing, ", "), func() { NewService(Deps{}) })
}
