package person_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// closedGate admits nothing: the engine is restarting.
type closedGate struct{}

func (closedGate) Begin() bool { return false }
func (closedGate) End()        {}

func TestARestartingEngineRunsNoPersonRequest(t *testing.T) {
	t.Parallel()
	l := &fakeLedger{}
	c := serveWith(t, person.Options{
		Allow: []uint32{personUID}, Agents: map[string]person.Ledger{"bot": l},
		PeerUID: peerIs(personUID), Gate: closedGate{},
	})
	_, err := c.Agent("bot").ListChanges(context.Background(), ledger.ChangeListParams{})
	require.ErrorContains(t, err, "restarting onto the upgraded basalt binary")
	require.ErrorContains(t, err, "nothing was run")
	require.Zero(t, l.calls.Load())
}
