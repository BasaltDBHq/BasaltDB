package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

type fakePortal struct {
	f  PortalFinding
	ok bool
}

func (p fakePortal) PortalFinding() (PortalFinding, bool) { return p.f, p.ok }

func portalStatus(t *testing.T, operatedBy string, p PortalReporter) guidance.StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Status.Portal = p
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

func portalCodes(r guidance.StatusReport) []string {
	out := make([]string, 0, len(r.Problems))
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

func TestAMismatchingPortalIsAWarningToSignNothingThere(t *testing.T) {
	t.Parallel()
	r := portalStatus(t, "", fakePortal{ok: true, f: PortalFinding{CheckedAt: statusNow, Mismatch: true, Summary: "2 DIFFERS, 1 MISSING"}})
	require.Equal(t, []string{problemPortalMismatch}, portalCodes(r))
	p := r.Problems[0]
	require.Equal(t, "WARNING", p.Severity)
	require.True(t, r.Ready, "a warning does not stop the tools")
	require.Contains(t, p.Message, "2 DIFFERS, 1 MISSING")
	require.Len(t, p.NextSteps, 1)
	require.Equal(t, toolresult.ActionAskPerson, p.NextSteps[0].Action)
	require.Empty(t, p.NextSteps[0].Command)
	require.Contains(t, p.PersonMessage, "Do not sign anything on it")
}

func TestNoPortalProblemWithoutAMismatch(t *testing.T) {
	t.Parallel()
	for name, p := range map[string]PortalReporter{
		"no reporter":   nil,
		"no check yet":  fakePortal{},
		"a clean check": fakePortal{ok: true, f: PortalFinding{CheckedAt: statusNow}},
	} {
		require.Empty(t, portalCodes(portalStatus(t, "", p)), name)
	}
}
