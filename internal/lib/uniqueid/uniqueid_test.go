package uniqueid

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestIDVersions(t *testing.T) {
	t.Parallel()
	text, err := uuid.Parse(New())
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), text.Version())

	id, err := NewUUID()
	require.NoError(t, err)
	require.Equal(t, uuid.Version(7), id.Version())

	require.Equal(t, uuid.Version(4), NewRandom().Version(), "an upload id reveals no time")
}
