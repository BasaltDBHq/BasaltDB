package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// belowFloor is the guard of a 0.0.1 install as the engine reads it:
// version 1, below the update floor.
func belowFloor(t *testing.T) guardmodel.Status {
	t.Helper()
	st := guard.StatusAt(1, guard.Migrations())
	require.True(t, st.BelowFloor)
	return st
}

// withUpdateLink gives the service the setup page's UPDATE link, as an
// engine that serves the setup jobs does.
func withUpdateLink(d *Deps) { d.Core.Commands = d.Core.Commands.UpdateLink(testUpdateLink) }

// A guard below the update floor (an install from 0.0.1) serves only
// status, and neither a refused tool nor status hands over the setup
// page's UPDATE link, which cannot update it: the person is told to remove
// the install and set up again, with the removal page's link. The steps
// keep the catalog's GUARD_OUTDATED shape on both kinds of engine.
func TestAGuardBelowTheUpdateFloorIsRemovedNotUpdated(t *testing.T) {
	t.Parallel()
	for _, operatedBy := range []string{"", mcpcontract.OperatedByAgent} {
		t.Run("operatedBy="+operatedBy, func(t *testing.T) {
			t.Parallel()
			probe := &fakeProbe{st: belowFloor(t)}
			s := operatedService(t, "darwin", "", operatedBy, withUpdateLink, func(d *Deps) { d.Status.Probe = probe })

			err := s.status.Admit(context.Background())
			var bf *guidance.GuardBelowFloorError
			require.ErrorAs(t, err, &bf)
			te := s.Failure("query", queryArgs0, err)
			require.Equal(t, guidance.CodeUnavailable, te.Code)
			require.Equal(t, guidance.ReasonGuardOutdated, te.Reason)
			stepcatalogtest.RequireObeysCatalog(t, stepcatalogtest.Case{Tool: "query", Args: queryArgs0}, te, operatedBy)
			requireRemoveNotUpdate(t, te, te.PersonMessage, te.Links)

			r, err := s.status.Status(context.Background())
			require.NoError(t, err)
			require.False(t, r.Ready)
			require.Equal(t, guardmodel.GuardOutdated, r.Guard.State)
			stepcatalogtest.RequireProblemObeysCatalog(t, r.Problems, r.Ready, guidance.ReasonGuardOutdated, operatedBy)
			p := findProblem(t, r, guidance.ReasonGuardOutdated)
			requireRemoveNotUpdate(t, r, p.PersonMessage, p.Links)
			for _, p := range r.Problems {
				require.NotEqual(t, string(toolresult.WarningGuardUpgradeAvailable), p.Code)
			}
		})
	}
}

// requireRemoveNotUpdate: body names the removal page and never the
// UPDATE link, and the person is told to remove and set up again.
func requireRemoveNotUpdate(t *testing.T, body any, person string, links []toolresult.Link) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), testUpdateLink, "no UPDATE link for a guard below the floor")
	require.Contains(t, person, "Remove the old install first")
	require.Contains(t, person, "set up again")
	require.Equal(t, []toolresult.Link{{Label: "Remove an older install", URL: guardmodel.RemoveOldInstallDoc}}, links)
}

// A guard at the floor or above that misses a breaking version still gets
// the UPDATE link.
func TestAnOutdatedGuardAboveTheFloorKeepsTheUpdateLink(t *testing.T) {
	t.Parallel()
	st := guard.StatusAt(2, guard.Migrations())
	require.False(t, st.BelowFloor)
	s := operatedService(t, "darwin", "", "", withUpdateLink, func(d *Deps) { d.Status.Probe = &fakeProbe{st: st} })
	te := s.Failure("query", queryArgs0, s.status.Admit(context.Background()))
	require.Equal(t, guidance.ReasonGuardOutdated, te.Reason)
	require.True(t, hasStep(te.NextSteps, toolresult.ActorPerson, toolresult.ActionOpenLink, testUpdateLink), "%+v", te.NextSteps)
}
