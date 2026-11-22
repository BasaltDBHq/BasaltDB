package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
)

// The revert page signs a widen proof over the select text it builds itself
// (web/lib/scope.js). The shared fixtures (internal/core/revert/testdata) give
// that text for each descriptor; here Postgres normalizes the same
// descriptors, so the page, Go and the guard agree byte for byte.
func TestRevertSelectFixturesMatchPostgres(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "core", "revert", "testdata", "fixtures.json"))
	require.NoError(t, err)
	var f struct {
		Rescope []struct {
			Name       string          `json:"name"`
			Select     json.RawMessage `json:"select"`
			SelectText string          `json:"selectText"`
		} `json:"rescope"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Rescope)
	d := guardtest.New(t)
	d.Init(t, guard.AgentSpec{Name: "bot", Password: guard.NewPassword()})
	for _, c := range f.Rescope {
		got := scalarOf[string](t, d.Admin, `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(c.Select))
		require.Equal(t, c.SelectText, got, c.Name)
	}
}
