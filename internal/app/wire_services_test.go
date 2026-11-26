package app

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The connect probe is wired with the reader of a refused login's server
// message, so Supabase's pooler not knowing the role counts as a refusal
// there as in basalt init --remote.
func TestWireHandoffReadsTheServerMessage(t *testing.T) {
	t.Parallel()
	o := wireHandoff(handoffOptions{})
	require.NotNil(t, o.Prober.Errors)
	noTenant := fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: setup.SQLStateInternal, Message: setup.SupavisorNoTenant})
	require.True(t, setup.LoginRefused(o.Prober.Errors, noTenant))
	require.True(t, setup.LoginProves(o.Prober.Errors, "verify-full", false, noTenant))
}
