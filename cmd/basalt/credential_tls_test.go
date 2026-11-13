package main

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// fakeProbe answers a probe login by the candidate's sslmode: a refused
// password (the login got through TLS and channel binding) for the modes
// in pass, ok for nothing else.
func fakeProbe(t *testing.T, pass map[string]bool, seen *[]string) func(context.Context, string) error {
	t.Helper()
	return func(_ context.Context, dsn string) error {
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		q := u.Query()
		*seen = append(*seen, q.Get(paramSSLMode)+"/"+q.Get(paramChannelBinding))
		if pass[q.Get(paramSSLMode)] {
			return &pgconn.PgError{Code: sqlstateInvalidPassword, Message: "password authentication failed"}
		}
		return errors.New("channel binding required, but server authenticated with SCRAM-SHA-256")
	}
}

func TestHardenedCredential(t *testing.T) {
	t.Parallel()
	const base = "postgres://basalt_agent_bot:pw@db.example.com:5432/postgres"
	for _, tc := range []struct {
		name, dsn string
		pass      map[string]bool
		want      string
		probes    []string
	}{
		{
			name: "verify-full where the certificate verifies", dsn: base, pass: map[string]bool{sslVerifyFull: true},
			want:   base + "?channel_binding=require&sslmode=verify-full",
			probes: []string{"verify-full/require"},
		},
		{
			name: "else require with channel binding", dsn: base + "?sslmode=prefer", pass: map[string]bool{sslRequire: true},
			want:   base + "?channel_binding=require&sslmode=require",
			probes: []string{"verify-full/require", "require/require"},
		},
		{
			name: "verify-ca is kept, never weakened to require", dsn: base + "?sslmode=verify-ca&sslrootcert=%2Fca.pem", pass: map[string]bool{sslVerifyCA: true},
			want:   base + "?channel_binding=require&sslmode=verify-ca&sslrootcert=%2Fca.pem",
			probes: []string{"verify-full/require", "verify-ca/require"},
		},
		{
			name: "no channel binding offered: unchanged", dsn: base + "?sslmode=require", pass: map[string]bool{},
			want:   base + "?sslmode=require",
			probes: []string{"verify-full/require", "require/require"},
		},
		{name: "sslmode=disable: unchanged, no probe", dsn: base + "?sslmode=disable", want: base + "?sslmode=disable"},
		{name: "a Unix socket: unchanged, no probe", dsn: "postgres://basalt_agent_bot:pw@/postgres?host=%2Fvar%2Frun%2Fpostgresql", want: "postgres://basalt_agent_bot:pw@/postgres?host=%2Fvar%2Frun%2Fpostgresql"},
	} {
		var seen []string
		got := hardenedCredential(context.Background(), fakeProbe(t, tc.pass, &seen), tc.dsn)
		require.Equal(t, tc.want, got, tc.name)
		require.Equal(t, tc.probes, seen, tc.name)
	}
}

func TestHardenedCredentialLeavesAnUnreachableDatabase(t *testing.T) {
	t.Parallel()
	dsn := "postgres://basalt_agent_bot:pw@db.example.com/postgres"
	got := hardenedCredential(context.Background(), func(context.Context, string) error { return context.DeadlineExceeded }, dsn)
	require.Equal(t, dsn, got)
}
