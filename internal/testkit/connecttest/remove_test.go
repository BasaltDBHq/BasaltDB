package connecttest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/testkit/connecttest"
)

func refusalReason(t *testing.T, err error) string {
	t.Helper()
	var ce *connect.Error
	require.True(t, errors.As(err, &ce), "%v", err)
	for _, d := range ce.Details() {
		v, derr := d.Value()
		require.NoError(t, derr)
		if r, ok := v.(*connectv1.Refusal); ok {
			return r.GetReason()
		}
	}
	t.Fatalf("no refusal detail in %v", err)
	return ""
}

// The Remove BasaltDB tab's two calls, with only the admin connection
// string: no setup code, no bot.
func TestRemoveThroughTheService(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.NewAgent(t, "sales_bot", nil, nil)
	ctx := context.Background()
	_, url := connecttest.Start(t)
	client := connectv1connect.NewSetupServiceClient(http.DefaultClient, url)

	checked, err := client.CheckRemove(ctx, connect.NewRequest(&connectv1.CheckRemoveRequest{DatabaseUrl: d.URL}))
	require.NoError(t, err)
	var database string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	require.Equal(t, database, checked.Msg.GetDatabase())
	require.Equal(t, []string{"sales_bot"}, checked.Msg.GetBots())
	require.Contains(t, checked.Msg.GetSql(), "DROP SCHEMA IF EXISTS basalt_meta CASCADE;")
	require.False(t, checked.Msg.GetSampleSchema())

	// A code that is not a setup code is refused before the login.
	_, err = client.RunRemove(ctx, connect.NewRequest(&connectv1.RunRemoveRequest{DatabaseUrl: d.URL, Code: "not-a-code"}))
	require.Equal(t, "NOT_A_SETUP_CODE", refusalReason(t, err))

	// The admin login is the confirmation: no typed name, and no hold
	// without a removal link's code.
	done, err := client.RunRemove(ctx, connect.NewRequest(&connectv1.RunRemoveRequest{DatabaseUrl: d.URL}))
	require.NoError(t, err)
	require.Equal(t, []string{"sales_bot"}, done.Msg.GetBots())
	require.Empty(t, done.Msg.GetTicket())
	var left bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'basalt_meta')`).Scan(&left))
	require.False(t, left)
}
