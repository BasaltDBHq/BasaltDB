package setupcode_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// TestPostgresAcceptsVerifier creates a role with a verifier made here as
// its PASSWORD and logs in with the password: Postgres stores the verifier
// as is and checks a SCRAM login against it.
func TestPostgresAcceptsVerifier(t *testing.T) {
	t.Parallel()
	db := guardtest.New(t)
	ctx := context.Background()

	password, err := setupcode.NewPassword()
	require.NoError(t, err)
	verifier, err := setupcode.NewVerifier(password)
	require.NoError(t, err)
	require.True(t, setupcode.ValidVerifier(verifier))

	role := db.Names.Prefix + "_agent_scram"
	// Plain SQL: DDL; the role name is generated and the verifier matches
	// ValidVerifier (base64 and fixed punctuation, no quote).
	_, err = db.Admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD '"+verifier+"'")
	require.NoError(t, err)

	var stored string
	err = db.Admin.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, role).Scan(&stored)
	require.NoError(t, err)
	require.Equal(t, verifier, stored, "Postgres stores the verifier as given")

	login := func(pw string) error {
		u, err := url.Parse(db.URL)
		require.NoError(t, err)
		u.User = url.UserPassword(role, pw)
		conn, err := pgdial.Connect(ctx, u.String())
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		var one int
		return conn.QueryRow(ctx, `SELECT 1`).Scan(&one)
	}
	if login("wrong-"+password) == nil {
		t.Skip("the test server does not check passwords (trust auth)")
	}
	require.NoError(t, login(password), "Postgres accepts the password behind the verifier")
}
