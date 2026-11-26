package setup

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// LoginRefused is any refusal of a login on any connection; LoginProves
// counts a refused password with channel binding in any sslmode, and any
// refusal without channel binding only under sslmode=verify-full. The
// server's message is read from the typed error, never from its text.
func TestLoginRefusedAndLoginProves(t *testing.T) {
	t.Parallel()
	wrap := func(err error) error { return fmt.Errorf("failed to connect: %w", err) }
	cases := []struct {
		name    string
		err     error
		refused bool
	}{
		{"a refused password", &pgconn.PgError{Code: "28P01", Message: "password authentication failed"}, true},
		{"no such role or a pg_hba refusal", &pgconn.PgError{Code: "28000", Message: "role does not exist"}, true},
		{"the pooler not knowing the user", &pgconn.PgError{Code: SQLStateInternal, Message: SupavisorNoTenant}, true},
		{"another internal error", &pgconn.PgError{Code: SQLStateInternal, Message: "something else"}, false},
		{"the no-tenant text in the detail only", &pgconn.PgError{Code: SQLStateInternal, Message: "x", Detail: SupavisorNoTenant}, false},
		{"another server error", &pgconn.PgError{Code: "57P03", Message: SupavisorNoTenant}, false},
		{"a client error", errors.New("tls: handshake failure"), false},
		{"no error", nil, false},
	}
	for _, tc := range cases {
		for _, err := range []error{tc.err, wrap(tc.err)} {
			name := fmt.Sprintf("%s (%v)", tc.name, err)
			if tc.err == nil {
				err = nil
			}
			require.Equal(t, tc.refused, LoginRefused(pgErrors{}, err), name)
			for _, mode := range []string{sslVerifyFull, sslVerifyCA, sslRequire, sslDefault, sslDisable} {
				require.Equal(t, mode == sslVerifyFull && tc.refused, LoginProves(pgErrors{}, mode, false, err), "%s without binding, %s", name, mode)
				binding := SQLStateOf(err) == sqlstateInvalidPassword
				require.Equal(t, binding, LoginProves(pgErrors{}, mode, true, err), "%s with binding, %s", name, mode)
			}
		}
	}
}

// The server's message is read only for an internal_error: a class 28
// refusal needs no reader, and without one the pooler's answer fails
// closed (no refusal, no proof) instead of panicking.
func TestLoginRefusedWithoutAReader(t *testing.T) {
	t.Parallel()
	noTenant := &pgconn.PgError{Code: SQLStateInternal, Message: SupavisorNoTenant}
	require.True(t, LoginRefused(nil, &pgconn.PgError{Code: "28P01"}))
	require.True(t, LoginRefused(nil, &pgconn.PgError{Code: "28000"}))
	require.False(t, LoginRefused(nil, &pgconn.PgError{Code: "57P03"}))
	require.False(t, LoginRefused(nil, noTenant))
	require.True(t, LoginProves(nil, sslVerifyFull, true, &pgconn.PgError{Code: "28P01"}))
	require.True(t, LoginProves(nil, sslVerifyFull, false, &pgconn.PgError{Code: "28000"}))
	require.False(t, LoginProves(nil, sslVerifyFull, false, noTenant))
}
