package localsetup

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// A cause keeps the SQLSTATE, the step and the server's message, and no
// password or connection string in any form the error can hold them.
func TestCauseRedactsPasswords(t *testing.T) {
	t.Parallel()
	agentPW := guard.NewPassword()
	admin := "postgres://postgres" + ":Tr0ub4dor%26x@db.ref.supabase.co:5432/postgres?sslmode=verify-full"
	pg := &pgconn.PgError{
		Code: "42501", Detail: "the statement was ALTER ROLE x PASSWORD '" + agentPW + "'",
		Message: "permission denied for postgres://postgres" + ":Tr0ub4dor&x@db.ref.supabase.co password=Tr0ub4dor&x PASSWORD '" + agentPW + "' and Tr0ub4dor&x alone",
	}
	err := scrub(setupFailed("install script", fmt.Errorf("init step 7: %w", pg)), admin)
	r := AsRefusal(err)
	require.Equal(t, CodeSetupFailed, r.Code)
	require.Equal(t, "install script, statement 7", r.Cause.Step)
	require.Equal(t, "42501", r.Cause.SQLState)
	require.Contains(t, r.Cause.Message, "permission denied for")
	require.Contains(t, r.Message, "lacks a privilege")
	require.Contains(t, r.Message, "42501")
	for _, s := range []string{r.Cause.Message, r.Cause.Step, r.Message} {
		require.NotContains(t, s, "Tr0ub4dor")
		require.NotContains(t, s, agentPW)
		require.NotContains(t, s, "postgres://")
		require.NotContains(t, s, "the statement was", "the detail is never kept")
	}

	guardErr := AsRefusal(setupFailed("register the passkey", &pgconn.PgError{Code: "BS008", Message: "LEDGER_INPUT_INVALID", Detail: "label is required"}))
	require.Equal(t, "LEDGER_INPUT_INVALID: label is required", guardErr.Cause.Message, "a guard refusal keeps its detail")

	plain := AsRefusal(scrub(errors.New("dial "+admin), admin))
	require.Equal(t, CodeSetupFailed, plain.Code)
	require.Empty(t, plain.Cause.SQLState)
	require.NotContains(t, plain.Cause.Message, "Tr0ub4dor")
	require.Equal(t, "Reading the database or running the setup failed; nothing changed.", plain.Message)
}

func TestDefaultPasskeyLabel(t *testing.T) {
	t.Parallel()
	host := func(name string, err error) func() (string, error) {
		return func() (string, error) { return name, err }
	}
	require.Equal(t, "Passkey on Imans-MacBook-Pro", defaultPasskeyLabel(host("Imans-MacBook-Pro.local", nil)))
	require.Equal(t, fallbackPasskeyLabel, defaultPasskeyLabel(host("", errors.New("no name"))))
	require.Equal(t, fallbackPasskeyLabel, defaultPasskeyLabel(host("💻", nil)))
	require.Equal(t, "Passkey on host", defaultPasskeyLabel(host("ho\nst", nil)))
	long := defaultPasskeyLabel(host(strings.Repeat("a", 300), nil))
	require.Len(t, long, maxLabel)
}
