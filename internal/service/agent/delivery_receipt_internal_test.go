package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/channel/channeltest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

func receiptService(t *testing.T, keys *channel.EngineKeys) *Service {
	t.Helper()
	now := time.Date(2026, 11, 14, 9, 30, 0, 500, time.UTC)
	s := &Service{deps: Deps{Core: CoreDeps{Name: "bot", Now: func() time.Time { return now }}}}
	s.wire()
	if keys != nil {
		s.deps.Delivery.Receipts = keys
	}
	return s
}

// signedRevert is a revert of run as Postgres shows it once signed.
func signedRevert(t *testing.T, status string, widened bool) action.Revert {
	t.Helper()
	id, run, change := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	b := revert.Binding{
		Kind: "REVERT", RevertID: id, Database: "app",
		Select: revert.Select{Scope: revert.ScopeRun, ScopeID: run, Agents: []string{"bot"}},
		Intent: "Undo", Rows: 1500, RowsHash: strings.Repeat("cd", 32), RequestedBy: "bot",
		ExpiresAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC), Batched: true, SampleHash: strings.Repeat("ef", 32),
	}
	text, err := json.Marshal(b)
	require.NoError(t, err)
	r := action.Revert{ID: id, Status: status, Rows: 1500, BindingText: string(text), ChangeID: &change, Batched: true}
	if widened {
		r.Widened, r.BindingText = true, ""
	}
	return r
}

func TestRevertReceiptWhileApplying(t *testing.T) {
	t.Parallel()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	r := signedRevert(t, ledger.RevertApplying, false)
	got, err := receiptService(t, keys).revert.revertReceipt(r)
	require.NoError(t, err)
	p, err := channeltest.VerifyReceipt(got.Token, keys.PublicKeySPKI())
	require.NoError(t, err)
	require.Equal(t, channel.ReceiptApplying, p.Status)
	require.Equal(t, r.ChangeID.String(), p.ChangeID)
	require.Equal(t, strings.Repeat("cd", 32), p.RowsHash)
	require.Equal(t, "2026-11-14T09:30:00Z", p.At, "UTC, whole seconds")
	require.Empty(t, got.Missing)
	require.True(t, strings.HasPrefix(got.Line, "Signed: Revert of run "), got.Line)
	mcptest.Require(t, got.Line, nil)
}

func TestRevertReceiptRefusesAnUnsignedRevert(t *testing.T) {
	t.Parallel()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	_, err = receiptService(t, keys).revert.revertReceipt(signedRevert(t, ledger.RevertPending, false))
	require.Error(t, err, "a receipt is made only once Postgres accepted the signature")
}

func TestRevertReceiptWidened(t *testing.T) {
	t.Parallel()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	got, err := receiptService(t, keys).revert.revertReceipt(signedRevert(t, ledger.RevertApplying, true))
	require.NoError(t, err)
	require.Empty(t, got.Token)
	require.Equal(t, NoReceiptWidened, got.Missing)
	require.Equal(t, "No receipt: the revert's scope was changed on the signing page (1500 rows to restore in batches). "+
		"If you did not change it, tell the agent at once.", got.Line)
}

func TestReceiptOnKeyError(t *testing.T) {
	t.Parallel()
	got, err := receiptService(t, nil).revert.revertReceipt(signedRevert(t, ledger.RevertApplied, false))
	require.NoError(t, err)
	require.Equal(t, Receipt{Missing: NoReceiptKeyError, Line: noReceiptKeyErrorLine}, got)
}

// A long headline is shortened in the line, never the id or the engine.
func TestReceiptLineFitsAndKeepsTheIDs(t *testing.T) {
	t.Parallel()
	p := channel.Receipt{ItemID: uuid.Must(uuid.NewV7()).String(), Headline: strings.Repeat("Update 3 rows in public.orders + ", 20) + "end."}
	line := receiptLine("Approved", "approval", p, "R68W FYxA cGgI jMEN")
	require.LessOrEqual(t, len([]rune(line)), maxReceiptLine)
	require.True(t, strings.HasSuffix(line, "... (approval "+p.ItemID+"), receipt from engine R68W FYxA cGgI jMEN."), line)
	short := receiptLine("Approved", "approval", channel.Receipt{ItemID: p.ItemID, Headline: "Delete 1 row in public.customers + 30 cascaded rows."}, "R68W FYxA cGgI jMEN")
	require.Equal(t, "Approved: Delete 1 row in public·customers + 30 cascaded rows (approval "+p.ItemID+"), receipt from engine R68W FYxA cGgI jMEN.", short)
}
