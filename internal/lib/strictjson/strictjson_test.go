package strictjson_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	var v struct{ A int }
	require.NoError(t, strictjson.Decode([]byte(`{"A":1} `), &v), "trailing whitespace is not data")
	require.Equal(t, 1, v.A)
	require.Error(t, strictjson.Decode([]byte(`{"A":1,"B":2}`), &v), "B is a field v does not have")
	require.ErrorIs(t, strictjson.Decode([]byte(`{"A":1} {"A":2}`), &v), strictjson.ErrTrailingData, "a second value after the first")
	require.ErrorIs(t, strictjson.Decode([]byte(`{"A":1}}`), &v), strictjson.ErrTrailingData, "a stray brace after the value")
	require.ErrorIs(t, strictjson.Decode([]byte(`{"A":1}]`), &v), strictjson.ErrTrailingData, "a stray bracket after the value")
	require.ErrorIs(t, strictjson.Decode([]byte(`{"A":1} x`), &v), strictjson.ErrTrailingData, "a byte that is not JSON after the value")
	require.Error(t, strictjson.Decode([]byte(``), &v), "an empty body holds no value")
}
