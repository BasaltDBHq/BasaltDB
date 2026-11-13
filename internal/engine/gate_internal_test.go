//go:build linux || darwin

package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// outdated refuses every call as Service.Admit does on an outdated guard.
func outdated(context.Context) error {
	return &mcp.ToolError{Code: "UNAVAILABLE", Reason: "GUARD_OUTDATED", Message: "the guard misses breaking migrations 18; run basalt upgrade --agent bot"}
}

// TestThePersonSocketAppliesNothingOnAnOutdatedGuard: the person socket's
// ledger is gated like the agent's tools, so basalt approve and basalt
// revert reach no database the guard check refuses. The inner ledger is
// nil: any call that got through would panic.
func TestThePersonSocketAppliesNothingOnAnOutdatedGuard(t *testing.T) {
	t.Parallel()
	dir, err := os.MkdirTemp("", "bgate") // short: Unix socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "person.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	srv := person.NewServer(person.Options{
		Allow: []uint32{4242}, Agents: map[string]person.Ledger{"bot": gatedLedger{admit: outdated}},
		AgentUIDs: map[string]uint32{"bot": 5001},
		PeerUID:   func(*net.UnixConn) (uint32, error) { return 4242, nil }, Log: slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	c := person.Client{Path: path}.Agent("bot")
	requireRefused := func(err error, what string) {
		t.Helper()
		var pe *person.Error
		require.True(t, errors.As(err, &pe), "%s: %v", what, err)
		require.Equal(t, person.CodeRefused, pe.Code, what)
		require.Contains(t, pe.Message, "basalt upgrade", what)
	}
	_, err = c.SubmitApproval(ctx, uuid.New(), passkey.Assertion{})
	requireRefused(err, "approve")
	_, err = c.ApplyRevert(ctx, uuid.New(), passkey.Assertion{})
	requireRefused(err, "revert")
	_, err = c.ListPasskeys(ctx)
	requireRefused(err, "passkey list")
}

// TestGatedLedgerRefusesEveryCall calls each Ledger method on a gated
// ledger with no inner ledger: each must be refused before it is reached.
func TestGatedLedgerRefusesEveryCall(t *testing.T) {
	t.Parallel()
	g, ctx, id := gatedLedger{admit: outdated}, context.Background(), uuid.New()
	calls := map[string]func() error{
		"CheckHealth":     func() error { _, err := g.CheckHealth(ctx, ledger.HealthOptions{}); return err },
		"ListChanges":     func() error { _, err := g.ListChanges(ctx, ledger.ChangeListParams{}); return err },
		"ListAccess":      func() error { _, err := g.ListAccess(ctx); return err },
		"RowChanges":      func() error { _, err := g.RowChanges(ctx, []uuid.UUID{id}); return err },
		"ListPasskeys":    func() error { _, err := g.ListPasskeys(ctx); return err },
		"FindApproval":    func() error { _, err := g.FindApproval(ctx, id); return err },
		"SubmitApproval":  func() error { _, err := g.SubmitApproval(ctx, id, passkey.Assertion{}); return err },
		"FindRevert":      func() error { _, err := g.FindRevert(ctx, id); return err },
		"PreviewRevert":   func() error { _, err := g.PreviewRevert(ctx, guard.RevertScope{}); return err },
		"PrepareRevert":   func() error { _, err := g.PrepareRevert(ctx, guard.RevertScope{}, "x"); return err },
		"ApplyRevert":     func() error { _, err := g.ApplyRevert(ctx, id, passkey.Assertion{}); return err },
		"ListRevertLines": func() error { _, err := g.ListRevertLines(ctx, ledger.RevertLineParams{}); return err },
	}
	var _ person.Ledger = g
	for name, call := range calls {
		var pe *person.Error
		require.ErrorAs(t, call(), &pe, name)
		require.Equal(t, person.CodeRefused, pe.Code, name)
	}

	// Served: the call reaches the ledger.
	served := gatedLedger{inner: passkeysOnly{}, admit: func(context.Context) error { return nil }}
	_, err := served.ListPasskeys(ctx)
	require.NoError(t, err)
}
