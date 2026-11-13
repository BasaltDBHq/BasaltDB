//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// emptyLedger is an agent with an intact, empty ledger and no passkey;
// approvals and reverts are not found.
type emptyLedger struct{}

func (emptyLedger) CheckHealth(context.Context, ledger.HealthOptions) (ledger.Health, error) {
	return ledger.Health{Chain: guard.ChainStatus{Intact: true}, LastHeartbeat: time.Now()}, nil
}

func (emptyLedger) ListChanges(context.Context, ledger.ChangeListParams) (pagination.Page[ledger.Change], error) {
	return pagination.Page[ledger.Change]{}, nil
}

func (emptyLedger) ListAccess(context.Context) (pgcatalog.Access, error) {
	return pgcatalog.Access{}, nil
}

func (emptyLedger) RowChanges(context.Context, []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error) {
	return map[uuid.UUID][]ledger.RowChange{}, nil
}

func (emptyLedger) ListPasskeys(context.Context) ([]ledger.Passkey, error) { return nil, nil }

func (emptyLedger) FindApproval(context.Context, uuid.UUID) (ledger.Approval, error) {
	return ledger.Approval{}, ledger.ErrApprovalNotFound
}

func (emptyLedger) SubmitApproval(context.Context, uuid.UUID, passkey.Assertion) (time.Time, error) {
	return time.Time{}, nil
}

func (emptyLedger) FindRevert(context.Context, uuid.UUID) (ledger.Revert, error) {
	return ledger.Revert{}, ledger.ErrRevertNotFound
}

func (emptyLedger) PreviewRevert(context.Context, guard.RevertScope) ([]string, error) {
	return nil, nil
}

func (emptyLedger) PrepareRevert(context.Context, guard.RevertScope, string) (guard.PreparedRevert, error) {
	return guard.PreparedRevert{}, nil
}

func (emptyLedger) ApplyRevert(context.Context, uuid.UUID, passkey.Assertion) (guard.AppliedRevert, error) {
	return guard.AppliedRevert{}, nil
}

func (emptyLedger) RescopeRevert(context.Context, uuid.UUID, []uuid.UUID, []string) (guard.PreparedRevert, error) {
	return guard.PreparedRevert{}, nil
}

func (emptyLedger) RejectRevert(context.Context, uuid.UUID, string) (guard.RejectedRevert, error) {
	return guard.RejectedRevert{}, nil
}

func (emptyLedger) ListRevertLines(context.Context, ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	return pagination.Page[ledger.RevertLine]{}, nil
}

// personUIDForTest stands in for the person's OS user.
const personUIDForTest = 4242

// personSocket serves agent bot on a person socket in a short temp dir,
// seeing every peer as peer.
func personSocket(t *testing.T, peer uint32) string {
	t.Helper()
	return personSocketFor(t, peer, emptyLedger{})
}

// personSocketFor is personSocket with agent bot's ledger given.
func personSocketFor(t *testing.T, peer uint32, l person.Ledger) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bcs")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "person.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	srv := person.NewServer(person.Options{
		Allow: []uint32{personUIDForTest}, Agents: map[string]person.Ledger{"bot": l},
		PeerUID: func(*net.UnixConn) (uint32, error) { return peer, nil },
		Log:     slog.New(slog.DiscardHandler),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

// serviceRun runs a person command as if the engine service were
// installed, with its person socket at socket and nothing in the env.
func serviceRun(t *testing.T, socket string, cmd func(*cliIO, []string) int, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr},
		func(k string) string { return map[string]string{envCacheDir: t.TempDir()}[k] })
	c.engine = engineAccess{unitInstalled: func() bool { return true }, personSocket: socket}
	code := cmd(c, args)
	return result{code, stdout.String(), stderr.String()}
}

type personCommand struct {
	name string
	run  func(*cliIO, []string) int
	args []string
}

func personCommands() []personCommand {
	id := uuid.NewString()
	return []personCommand{
		{"log", runLog, []string{"--agent", "bot"}},
		{"approve", runApprove, []string{"--agent", "bot", "--show", id}},
		{"revert", runRevert, []string{"--agent", "bot", "--status", id}},
	}
}

func TestServiceModeWithTheEngineStoppedSaysSo(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "person.sock")
	for _, pc := range personCommands() {
		r := serviceRun(t, missing, pc.run, pc.args...)
		require.Equal(t, exitError, r.code, pc.name)
		require.Contains(t, r.stderr, "basalt: the engine is not running; start it with "+service.StartCommand(runtime.GOOS)+", then run this command again", pc.name)
		require.NotContains(t, r.stderr, "permission denied", pc.name)
		require.NotContains(t, r.stderr, "engine.json", "never a fallback to the files")
	}
}

func TestServiceModeWithARefusedUIDSaysHowToAddIt(t *testing.T) {
	t.Parallel()
	socket := personSocket(t, personUIDForTest+1)
	for _, pc := range personCommands() {
		r := serviceRun(t, socket, pc.run, pc.args...)
		require.Equal(t, exitError, r.code, pc.name)
		uid := os.Getuid()
		require.Contains(t, r.stderr, fmt.Sprintf("basalt: the engine does not let OS user %d use its person socket; add it with sudo basalt init --agent bot --person-uid %d", uid, uid), pc.name)
		require.NotContains(t, r.stderr, "permission denied", pc.name)
	}
}

func TestServiceModeGoesThroughThePersonSocket(t *testing.T) {
	t.Parallel()
	socket := personSocket(t, personUIDForTest)

	r := serviceRun(t, socket, runLog, "--agent", "bot")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "warning: no active passkey", "the engine's answer, printed as in same-user mode")

	id := uuid.NewString()
	r = serviceRun(t, socket, runApprove, "--agent", "bot", "--show", id)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "approval "+id+" is not a held write of this agent")

	r = serviceRun(t, socket, runRevert, "--agent", "bot", "--status", id)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no revert "+id+" prepared with this agent's credential")

	r = serviceRun(t, socket, runLog, "--agent", "other")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, `the engine serves no agent "other"`)
}

func TestSameUserModeReadsTheFiles(t *testing.T) {
	t.Parallel()
	cfg := filepath.Join(t.TempDir(), "engine.json")
	socket := filepath.Join(t.TempDir(), "person.sock")
	var stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &bytes.Buffer{}, err: &stderr}, func(string) string { return "" })

	def := config.DefaultPath(runtime.GOOS)
	// No unit: the files, as before.
	c.engine = engineAccess{unitInstalled: func() bool { return false }, personSocket: socket}
	require.False(t, c.serviceMode("bot", "", def))
	// A unit, but a config, a credential file or the env given: the files.
	c.engine.unitInstalled = func() bool { return true }
	require.True(t, c.serviceMode("bot", "", def))
	require.False(t, c.serviceMode("bot", "", cfg))
	require.False(t, c.serviceMode("bot", "/tmp/bot.url", def))
	require.False(t, c.serviceMode("", "", def))
	c.getenv = func(k string) string { return map[string]string{envAgentURL: "postgres://x"}[k] }
	require.False(t, c.serviceMode("bot", "", def))

	// Same-user mode with a missing config names the config, as before.
	c.getenv = func(string) string { return "" }
	code := runLog(c, []string{"--agent", "bot", "--config", cfg})
	require.Equal(t, exitError, code)
	require.Contains(t, stderr.String(), cfg)
	require.NotContains(t, stderr.String(), "the engine is not running")
}
