package pgdial_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// ConnTarget reads the first host and port, and whether the TLS check uses
// the system's roots: TLS that verifies with no root certificate given.
func TestConnTargetReadsTheHostAndTheRoots(t *testing.T) {
	t.Parallel()
	got, err := pgdial.ConnTarget("postgres://bot@db.example.com:6543/app?sslmode=verify-full")
	require.NoError(t, err)
	require.Equal(t, pgdial.TLSTarget{Host: "db.example.com", Port: 6543, SystemRoots: true}, got)
	got, err = pgdial.ConnTarget("postgres://bot@db.example.com/app?sslmode=disable")
	require.NoError(t, err)
	require.Equal(t, pgdial.TLSTarget{Host: "db.example.com", Port: 5432}, got)
	_, err = pgdial.ConnTarget("postgres://bot@db.example.com:notaport/app")
	require.Error(t, err)
}

// SSLMode is the sslmode a URL or a key=value string names, "" for none.
func TestSSLMode(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"postgres://u@db.example.com/app?sslmode=require":         "require",
		"postgresql://u@db.example.com/app?a=1&sslmode=verify-ca": "verify-ca",
		"postgres://u@db.example.com/app":                         "",
		"host=db.example.com sslmode=disable dbname=app":          "disable",
		"host=db.example.com sslmode='verify-full'":               "verify-full",
		"host=db.example.com":                                     "",
	} {
		require.Equal(t, want, pgdial.SSLMode(in), in)
	}
}
