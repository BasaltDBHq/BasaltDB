package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// fixedRand is a deterministic randomness source, so a test can build the
// same registration request basalt init builds.
func fixedRand() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)) }

// cliRand is cli with a fixed randomness source.
func cliRand(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string { return env[k] })
	c.rand = fixedRand()
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

// registrationCode is what the registration page returns for the request
// basalt init makes with fixedRand on database db.
func registrationCode(t *testing.T, person *passkeytest.Authenticator, db string) string {
	t.Helper()
	req, err := passkey.NewRegistrationRequest(fixedRand(), db, "BasaltDB · "+db)
	require.NoError(t, err)
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	code, err := resp.Code()
	require.NoError(t, err)
	return code
}

func dbName(t *testing.T, d *guardtest.DB) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(d.URL)
	require.NoError(t, err)
	return cfg.Database
}

// initWithPasskey sets up agent bot in d with the person's portal passkey
// registered, and returns the agent's credential file.
func initWithPasskey(t *testing.T, d *guardtest.DB, person *passkeytest.Authenticator) string {
	t.Helper()
	return setUpAgent(t, d, filepath.Join(t.TempDir(), "engine.json"), "bot", agentFixture{write: []string{"public.leads"}, person: person})
}
