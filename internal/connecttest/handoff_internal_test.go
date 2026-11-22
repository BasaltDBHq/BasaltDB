package connecttest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// CheckSetup replaces a PREVIEW hold and never a SET_UP one; RunSetup
// replaces either; RUN_ELSEWHERE looks at SET_UP holds only (CONTRACT.md,
// Connect, The reach check).
func TestHoldPhasesRank(t *testing.T) {
	t.Parallel()
	s, _ := Start(t)
	d := setup.Description{SetupID: "01a1f78c-52b8-7c3a-9f00-0000000000e1", EngineKey: "key", Fingerprint: "734b aaea 804e 1065 4148"}
	mine := setup.Target{Host: "db.example.com", Port: 5432, Database: "app"}
	other := setup.Target{Host: "other.example.com", Port: 5432, Database: "app"}

	ticket, err := s.previewFor(d, other, "")
	require.NoError(t, err)
	require.NotEmpty(t, ticket)
	require.False(t, s.otherTarget(d, mine), "a PREVIEW hold never refuses anything")
	ticket, err = s.previewFor(d, mine, "")
	require.NoError(t, err)
	require.NotEmpty(t, ticket, "a preview replaces a preview")
	held, _ := s.Held(d.SetupID)
	require.Equal(t, mine, held)

	_, err = s.holdFor(d, mine, "")
	require.NoError(t, err)
	require.Equal(t, PhaseSetUp, s.HeldPhase(d.SetupID))
	ticket, err = s.previewFor(d, other, "")
	require.NoError(t, err)
	require.Empty(t, ticket, "no preview while a SET_UP hold exists")
	held, _ = s.Held(d.SetupID)
	require.Equal(t, mine, held)
	require.True(t, s.otherTarget(d, other))
	require.False(t, s.otherTarget(d, setup.Target{Host: "DB.example.com", Port: 5432, Database: "app"}), "compared in the canonical form")
}
