package chainpin_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/chainpin"
)

// Install ids for the tests.
var (
	installA = uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2b")
	installB = uuid.MustParse("0193a1b2-c3d4-4e5f-8a6b-7c8d9e0f1a2c")
)

// genesis is the head before the first ledger entry: seq 0, a zero sha256.
var genesis = action.ChainHead{Seq: 0, Hash: make([]byte, 32)}

func TestMemory(t *testing.T) {
	t.Parallel()
	var m chainpin.Memory
	_, ok, err := m.Load("bot")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, m.Save("bot", chainpin.Pin{Head: genesis, Install: installA}))
	got, ok, err := m.Load("bot")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, chainpin.Pin{Head: genesis, Install: installA}, got)
}

// A pin belongs to the install it was saved on; one saved before install
// ids (none) is of no install, so it is settled, never checked as the
// current one's.
func TestPinOfInstall(t *testing.T) {
	t.Parallel()
	require.True(t, chainpin.Pin{Install: installA}.Of(installA))
	require.False(t, chainpin.Pin{Install: installA}.Of(installB))
	require.False(t, chainpin.Pin{}.Of(installB))
	require.False(t, chainpin.Pin{}.Of(uuid.Nil))
}
