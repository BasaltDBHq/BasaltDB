package localsetup_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
)

// The link vector the setup page's parser reads too (web/lib/setup.test.mjs).
type linkVector struct {
	Origin string         `json:"origin"`
	Job    localsetup.Job `json:"job"`
	Link   string         `json:"link"`
}

func TestLinkMatchesTheSharedVector(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/link.json")
	require.NoError(t, err)
	var v linkVector
	require.NoError(t, json.Unmarshal(raw, &v))
	got, err := localsetup.Link(v.Origin, v.Job)
	require.NoError(t, err)
	require.Equal(t, v.Link, got)

	_, err = localsetup.Link("http://localhost:8787/", v.Job)
	require.Error(t, err)
}
