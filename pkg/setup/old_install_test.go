package setup_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// A database with an older BasaltDB install this build cannot use (here
// one from before the guard's versions started again at 1: no installs
// table, a version this build does not have) is refused at Check, before
// the person approves anything, and Run changes nothing.
func TestCheckRefusesAnOlderInstall(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	ctx := context.Background()
	d.Init(t, guardmodel.AgentSpec{Name: "other", Password: guard.NewPassword(), Write: []string{"public.leads"}})
	d.Exec(t, `SET ROLE `+d.Names.Guard()+`;
		DROP TABLE basalt_meta.installs CASCADE;
		INSERT INTO basalt_meta.schema_version (version) VALUES (30);
		RESET ROLE`)
	code := newCode(t, d, nil)

	_, err := setup.Check(ctx, d.Admin, request(code))
	require.Equal(t, setup.CodeSetupFailed, codeOf(t, err))
	require.Contains(t, err.Error(), "older BasaltDB install")
	require.Contains(t, err.Error(), "docs/remove-old-install.md")
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Equal(t, setup.CodeSetupFailed, codeOf(t, err))
	var versions int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(*) FROM basalt_meta.schema_version WHERE version = 30`).Scan(&versions))
	require.Equal(t, 1, versions, "nothing changed")
}
