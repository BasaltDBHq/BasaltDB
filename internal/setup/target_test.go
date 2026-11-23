package setup_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// An admin connection passes the target check on the code's host, port and
// database, with fallbacks on that same host and port only.
func TestCheckConnTarget(t *testing.T) {
	t.Parallel()
	p := setupcode.Payload{Target: &setupcode.Target{Host: "db.example.com", Port: 5432, Database: "app"}}
	at := setup.ConnConfig{
		Host: "db.example.com", Port: 5432, Database: "app", User: "admin",
		Fallbacks: []setup.ConnHost{{Host: "DB.example.com", Port: 5432}},
	}
	require.NoError(t, setup.CheckConnTarget(p, at))

	other := at
	other.Database = "other"
	var refusal *setup.SetuprunRefusalError
	require.True(t, errors.As(setup.CheckConnTarget(p, other), &refusal))
	require.Equal(t, setup.SetuprunCodeTargetMismatch, refusal.Code)

	several := at
	several.Fallbacks = []setup.ConnHost{{Host: "replica.example.com", Port: 5432}}
	err := setup.CheckConnTarget(p, several)
	require.ErrorContains(t, err, "several hosts")

	// A connect-only code has no target: any database is the setup's.
	require.NoError(t, setup.CheckConnTarget(setupcode.Payload{}, other))
}
