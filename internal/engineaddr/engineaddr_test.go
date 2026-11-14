package engineaddr_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engineaddr"
)

// vectors are the addresses every checker of the grammar runs: this
// package and web/lib/engineaddr.js (the portal's pin page and its edge
// function) read the same file.
type vectors struct {
	Accept map[string]string `json:"accept"`
	Refuse []string          `json:"refuse"`
}

func TestParse(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/addresses.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(b, &v))
	require.NotEmpty(t, v.Accept)
	require.NotEmpty(t, v.Refuse)
	for in, want := range v.Accept {
		got, err := engineaddr.Parse(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, in := range v.Refuse {
		_, err := engineaddr.Parse(in)
		require.ErrorIs(t, err, engineaddr.ErrInvalid, in)
	}
}
