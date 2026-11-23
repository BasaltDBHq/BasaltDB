package agent

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// This file tests finishing a setup from the laptop on the engine
// (CONTRACT.md, Setup from your laptop, On the engine; RI-10): the setup is
// cleared from engine.json only when the database, read with the agent's
// own credential, shows its setupId recorded, and the tools are served
// right after, with no restart.

// finishCall is one call of fakeFinisher.Finish.
type finishCall struct {
	id      string
	promote bool
}

// fakeFinisher answers PendingRecorded as set and records Finish calls.
type fakeFinisher struct {
	mu                    sync.Mutex
	pendingRecorded, has  bool
	pendingErr, finishErr error
	calls                 []finishCall
}

func (f *fakeFinisher) PendingRecorded(context.Context, uuid.UUID) (bool, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pendingRecorded, f.has, f.pendingErr
}

func (f *fakeFinisher) Finish(_ context.Context, id string, promote bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, finishCall{id: id, promote: promote})
	return f.finishErr
}

func (f *fakeFinisher) finished() []finishCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]finishCall(nil), f.calls...)
}

// finishing is a service with a pending setup, the probe and finisher given
// and n passkeys.
func finishing(probe *fakeProbe, fin *fakeFinisher, setup *config.Setup, passkeys int) *Service {
	d := deps()
	d.Status.Probe = probe
	d.Status.Finisher = fin
	setApprovals(&d, keys{n: passkeys})
	d.Status.Setup = setup
	d.Core.Now = func() time.Time { return statusNow }
	return NewService(d)
}

func pendingInstall() *config.Setup {
	return pendingSetup(guardmodel.SetupInstall, statusNow.Add(time.Hour))
}

// Each check the clear depends on, failing alone: nothing is cleared, the
// tools stay held, and status still reports the pending setup.
func TestASetupIsClearedOnlyWhenTheDatabaseShowsItRecorded(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		probe *fakeProbe
		fin   *fakeFinisher
		// held: the tools answer SETUP_PENDING (else another UNAVAILABLE).
		held bool
	}{
		{"the role cannot log in yet", &fakeProbe{err: errNoRole, recordedErr: errNoRole}, &fakeFinisher{}, true},
		{"the role logs in but the setup is not recorded", &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}, &fakeFinisher{}, true},
		{"the database cannot be reached", &fakeProbe{err: context.DeadlineExceeded, recordedErr: context.DeadlineExceeded}, &fakeFinisher{}, false},
		{
			"the pending credential is refused and the engine's finds nothing",
			&fakeProbe{err: errNoRole, recordedErr: errNoRole}, &fakeFinisher{has: false}, true,
		},
		{
			"the pending credential logs in but the setup is not recorded",
			&fakeProbe{err: errNoRole, recordedErr: errNoRole}, &fakeFinisher{has: true}, true,
		},
		{
			"the pending credential's read fails",
			&fakeProbe{err: errNoRole, recordedErr: errNoRole}, &fakeFinisher{pendingRecorded: true, has: true, pendingErr: errors.New("mode 644")}, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := finishing(tc.probe, tc.fin, pendingInstall(), 1)
			err := svc.Admit(context.Background())
			require.Error(t, err)
			if tc.held {
				var se *guidance.SetupError
				require.ErrorAs(t, err, &se)
			}
			r, err := svc.Status(context.Background())
			require.NoError(t, err)
			require.Equal(t, handoff.SetupPending, r.Setup.State)
			require.Empty(t, tc.fin.finished(), "nothing is cleared")
			require.NotNil(t, svc.status.pending.Pending(), "the setup stays pending")
		})
	}
}

// After the laptop init, status finds the setup recorded with the engine's
// own credential: it clears it, reports DONE, and the tools are served
// without a restart. A missing passkey is NO_PASSKEY, a usual problem, not
// a setup that never finishes (RI-10).
func TestAfterTheLaptopStatusClearsTheSetupAndTheToolsAreServed(t *testing.T) {
	t.Parallel()
	setup := pendingInstall()
	probe := &fakeProbe{err: errNoRole, recordedErr: errNoRole}
	fin := &fakeFinisher{}
	svc := finishing(probe, fin, setup, 0)
	srv, tools := serverOf(svc)
	requireOnlyStatusServed(t, srv, tools, guidance.ReasonSetupPending, testFingerprint)

	// The person ran the code on their computer.
	id := uuid.MustParse(setup.SetupID)
	probe.err, probe.recordedErr, probe.recorded = nil, nil, true
	probe.st = guardAt(guardmodel.GuardOK, nil, nil)
	probe.latest = &guardmodel.AgentSetup{SetupID: id, Kind: guardmodel.SetupInstall}

	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, guidance.SetupStatus{State: handoff.SetupDone, SetupID: setup.SetupID, Kind: guardmodel.SetupInstall}, r.Setup)
	require.Equal(t, []finishCall{{id: setup.SetupID, promote: false}}, fin.finished())
	require.Nil(t, svc.status.pending.Pending(), "forgotten in memory too")
	p := findProblem(t, r, problemNoPasskey)
	require.Equal(t, mcpcontract.SeverityError, p.Severity)
	require.False(t, r.Ready, "nothing held can be approved yet")
	// Not ready holds no tool: reads and writes under the hold limit run.

	body, isError := serveCall(t, srv, "run_start", map[string]any{"intent": "x"})
	require.False(t, isError, "served with no restart: %v", body)

	// Once cleared, a call reads no setup and clears nothing more.
	probe.recorded = false
	require.NoError(t, svc.Admit(context.Background()))
	require.Len(t, fin.finished(), 1)
}

// A rotation waits in the .pending credential: when it logs in and finds the
// setup, the engine promotes it and clears the setup, even though its own
// password no longer works.
func TestAPendingCredentialThatFindsTheSetupIsPromoted(t *testing.T) {
	t.Parallel()
	setup := pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour))
	probe := &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recordedErr: errNoRole}
	fin := &fakeFinisher{pendingRecorded: true, has: true}
	svc := finishing(probe, fin, setup, 1)

	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, []finishCall{{id: setup.SetupID, promote: true}}, fin.finished())
	require.Nil(t, svc.status.pending.Pending())
	require.NotEqual(t, handoff.SetupPending, r.Setup.State)
}

// A promotion that fails leaves the engine on its old password, and a lock
// held by basalt init --remote is transient: the setup stays pending in
// memory and the next call tries again. A clear that fails otherwise (the
// config cannot be written) still serves the agent: the database decides,
// not the file.
func TestAFailedFinishIsTriedAgainWhenItCanStillWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for name, fin := range map[string]*fakeFinisher{
		"promotion failed": {pendingRecorded: true, has: true, finishErr: errors.New("the .pending file changed")},
		"lock held":        {finishErr: config.ErrLocked},
	} {
		svc := finishing(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recorded: true}, fin, pendingInstall(), 1)
		require.NoError(t, svc.Admit(ctx), "%s: recorded, so served", name)
		require.NotNil(t, svc.status.pending.Pending(), name)
		require.NoError(t, svc.Admit(ctx), name)
		require.Len(t, fin.finished(), 2, "%s: tried again", name)
	}

	fin := &fakeFinisher{finishErr: errors.New("read-only file system")}
	svc := finishing(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recorded: true}, fin, pendingInstall(), 1)
	require.NoError(t, svc.Admit(ctx))
	require.Nil(t, svc.status.pending.Pending())
	require.NoError(t, svc.Admit(ctx))
	require.Len(t, fin.finished(), 1)
}

// The heartbeat finishes a pending AGENT or UPGRADE setup too, which never
// holds the tools, so a rotation is picked up when nobody calls status.
func TestTheHeartbeatFinishesAChangeSetup(t *testing.T) {
	t.Parallel()
	setup := pendingSetup(guardmodel.SetupUpgrade, statusNow.Add(time.Hour))
	fin := &fakeFinisher{}
	svc := finishing(&fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recorded: true}, fin, setup, 1)
	require.NoError(t, svc.Admit(context.Background()))
	require.Empty(t, fin.finished(), "a call does not look for a change setup")
	require.NoError(t, svc.AdmitTick(context.Background()))
	require.Equal(t, []finishCall{{id: setup.SetupID}}, fin.finished())
}

// countingProbe counts the reads of the pending setup.
type countingProbe struct {
	*fakeProbe
	mu    sync.Mutex
	reads int
}

func (p *countingProbe) SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error) {
	p.mu.Lock()
	p.reads++
	p.mu.Unlock()
	return p.fakeProbe.SetupRecorded(ctx, id)
}

func (p *countingProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reads
}

// Held calls trust a not-recorded answer for a few seconds, so a burst of
// calls costs one read; status always reads afresh.
func TestHeldCallsTrustANotRecordedAnswerBriefly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	probe := &countingProbe{fakeProbe: &fakeProbe{err: errNoRole, recordedErr: errNoRole}}
	now := statusNow
	d := deps()
	d.Status.Probe, d.Status.Finisher, d.Status.Setup = probe, &fakeFinisher{}, pendingInstall()
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return now }
	svc := NewService(d)

	for range 5 {
		require.Error(t, svc.Admit(ctx))
	}
	require.Equal(t, 1, probe.count(), "one read for the burst")

	_, err := svc.Status(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, probe.count(), "status reads afresh")

	now = now.Add(handoff.NotRecordedFor)
	require.Error(t, svc.Admit(ctx))
	require.Equal(t, 3, probe.count(), "read again once the answer is old")
}

// serverOf is svc's MCP server and tools.
func serverOf(svc *Service) (*mcpserver.Server, []mcpserver.Tool) {
	tools := Tools(svc)
	return mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, mcpserver.ToolsFrom(tools, WithMeta)...), mcpserver.ToolsFrom(tools, WithMeta)
}

// A lock file the engine cannot open is reported, not retried in silence,
// and the setup stays pending until a try opens it (CONTRACT.md, Lock
// files).
func TestUnusableLockFileIsAStatusProblem(t *testing.T) {
	t.Parallel()
	const lock = "/etc/basalt/engine.json.lock"
	d := deps()
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil), recorded: true}
	setApprovals(&d, keys{n: 1})
	d.Status.Setup = pendingSetup(guardmodel.SetupAgent, statusNow.Add(time.Hour))
	d.Core.Now = func() time.Time { return statusNow }
	fin := &fakeFinisher{finishErr: &config.LockUnusableError{Path: lock, Err: os.ErrPermission}}
	d.Status.Finisher = fin
	svc := NewService(d)

	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	var found *guidance.Problem
	for i := range r.Problems {
		if r.Problems[i].Code == problemLockFileUnusable {
			found = &r.Problems[i]
		}
	}
	require.NotNil(t, found, "%+v", r.Problems)
	require.Contains(t, found.PersonMessage, lock)
	require.Equal(t, "sudo chown "+handoff.EngineUserName()+" "+lock, found.NextSteps[0].Command)
	require.Equal(t, toolresult.ActorPerson, found.NextSteps[0].Actor)
	require.NotNil(t, svc.status.pending.Pending(), "still pending: the next call tries again")

	fin.mu.Lock()
	fin.finishErr = nil
	fin.mu.Unlock()
	r, err = svc.Status(context.Background())
	require.NoError(t, err)
	for _, p := range r.Problems {
		require.NotEqual(t, problemLockFileUnusable, p.Code, "fixed: no problem")
	}
	require.Nil(t, svc.status.pending.Pending(), "finished once the lock opens")
	require.Len(t, fin.finished(), 2)
}
