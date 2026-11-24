package pgdial_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// CheckForeignDSN takes only a URL pgx reads no file for: an exact
// lower-case scheme, a password, no '#', ';' or whitespace, only the
// allowed parameters, and pgx's parse agreeing with Go's on the host, port,
// database and password.
func TestCheckForeignDSN(t *testing.T) {
	t.Parallel()
	for _, dsn := range []string{
		"postgres://u:pw@db.example.com/app?sslmode=require&default_query_exec_mode=exec",
		"postgresql://u:pw@db.example.com:5433/app",
		"postgres://u:pw@db.example.com/app?sslmode=prefer",
		"postgres://u:pw@db.example.com/app?sslmode=verify-full&channel_binding=require&application_name=bot",
		"postgres://u:pw@db.example.com/app?connect_timeout=5&target_session_attrs=read-write&require_auth=scram-sha-256",
		"postgres://u:pw@db.example.com/app?sslnegotiation=direct&sslsni=1&min_protocol_version=3.0&max_protocol_version=3.2",
		"postgres://u:p%40ss%2Fw@db.example.com/app",
		"postgres://u:pw@[2001:db8::1]:5432/app",
		"postgres://u:pw@db.example.com",
	} {
		require.NoError(t, pgdial.CheckForeignDSN(dsn), dsn)
	}
	for name, dsn := range map[string]string{
		"sslcert":                  "postgres://u:pw@db.example.com/app?sslcert=/root/c",
		"sslkey":                   "postgres://u:pw@db.example.com/app?sslkey=/root/k",
		"sslrootcert":              "postgres://u:pw@db.example.com/app?sslrootcert=/root/ca.pem",
		"sslcrl":                   "postgres://u:pw@db.example.com/app?sslcrl=/root/crl",
		"sslpassword":              "postgres://u:pw@db.example.com/app?sslpassword=x",
		"passfile":                 "postgres://u:pw@db.example.com/app?passfile=/root/.pgpass",
		"service":                  "postgres://u:pw@db.example.com/app?service=prod",
		"servicefile":              "postgres://u:pw@db.example.com/app?servicefile=/root/.pg_service.conf",
		"an unknown parameter":     "postgres://u:pw@db.example.com/app?options=-c%20x",
		"host as a parameter":      "postgres://u:pw@db.example.com/app?host=/var/run/postgresql",
		"port as a parameter":      "postgres://u:pw@db.example.com/app?port=6543",
		"dbname as a parameter":    "postgres://u:pw@db.example.com/app?dbname=postgres",
		"user as a parameter":      "postgres://u:pw@db.example.com/app?user=postgres",
		"password as a parameter":  "postgres://u@db.example.com/app?password=pw",
		"no password":              "postgres://u@db.example.com/app",
		"an empty password":        "postgres://u:@db.example.com/app",
		"no user info":             "postgres://db.example.com/app",
		"keyword/value":            "host=db.example.com password=pw",
		"an upper-case scheme":     "POSTGRES://u:pw@db.example.com/app",
		"another scheme":           "mysql://u:pw@db.example.com/app",
		"a fragment":               "postgres://u:pw@db.example.com/app#&passfile=/root/.pgpass",
		"a semicolon":              "postgres://u:pw@db.example.com/app?sslmode=require;passfile=/root/.pgpass",
		"a space":                  "postgres://u:pw@db.example.com/app?sslmode=require passfile=/root/.pgpass",
		"a newline":                "postgres://u:pw@db.example.com/app\npassfile=/root/.pgpass",
		"a tab":                    "postgres://u:pw@db.example.com/app\t",
		"a control character":      "postgres://u:pw@db.example.com/app\x7f",
		"a NUL":                    "postgres://u:pw@db.example.com/app\x00",
		"several hosts":            "postgres://u:pw@db.example.com,other.example.com/app",
		"a port out of range":      "postgres://u:pw@db.example.com:70000/app",
		"a port that is no number": "postgres://u:pw@db.example.com:x/app",
		"a socket path host":       "postgres://u:pw@%2Fvar%2Frun%2Fpostgresql/app",
		"empty":                    "",
	} {
		require.ErrorIs(t, pgdial.CheckForeignDSN(dsn), pgdial.ErrForeignDSN, name)
	}
	require.Contains(t, pgdial.ErrForeignDSN.Error(), "application_name, channel_binding")
}

// The refusal never echoes the string, which holds a password.
func TestCheckForeignDSNNeverEchoesTheString(t *testing.T) {
	t.Parallel()
	err := pgdial.CheckForeignDSN("postgres://u:hunter2-secret@db.example.com/app?passfile=/root/.pgpass")
	require.ErrorIs(t, err, pgdial.ErrForeignDSN)
	require.NotContains(t, err.Error(), "hunter2-secret")
	require.NotContains(t, err.Error(), "/root/.pgpass")
}
