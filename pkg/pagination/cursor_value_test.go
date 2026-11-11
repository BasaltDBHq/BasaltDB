package pagination

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeValueCursor(t *testing.T) {
	t.Parallel()
	id := "018f3b2a-7c2d-7abc-8000-000000000001"
	c := EncodeValueCursor(int64(42), id)
	v, gotID, err := DecodeValueCursor(c)
	require.NoError(t, err)
	require.Equal(t, id, gotID)
	require.Equal(t, float64(42), v)

	c2 := EncodeValueCursor("z", id)
	v2, _, err := DecodeValueCursor(c2)
	require.NoError(t, err)
	require.Equal(t, "z", v2)
}
