package setup

import (
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// TestCertificateKindIsWhatTheEngineDialsWith: the confirm step's kind of
// an admin string follows what verifies it: a built-in profile is the
// provider's, an operator's profile or the string's own root is OWN, a
// host no profile covers is PUBLIC, and below verify-full nothing
// verifies it.
func TestCertificateKindIsWhatTheEngineDialsWith(t *testing.T) {
	t.Parallel()
	operator := &trustprofile.Profile{Spec: trustprofile.Spec{Name: trustprofile.PinName("db.example"), Match: []string{"=db.example"}}, Origin: trustprofile.Operator}
	s, err := NewLocal(LocalOptions{
		Backend:    testBackend{},
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
		Profiles: func() *trustprofile.Set {
			return trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{operator}, nil)
		},
	})
	require.NoError(t, err)
	root := filepath.Join(t.TempDir(), "root.crt")
	ca, _ := trustprofiletest.Chain(t, "public.example")
	require.NoError(t, os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600))

	for _, tc := range []struct {
		dsn      string
		kind     string
		provider string
	}{
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=verify-full", certProvider, "supabase"},
		{"postgres://u@x.rds.amazonaws.com:5432/app?sslmode=verify-full", certProvider, "aws-rds"},
		{"postgres://u@db.example:5432/app?sslmode=verify-full", certOwn, ""},
		{"postgres://u@public.example:5432/app?sslmode=verify-full", certPublic, ""},
		{"postgres://u@public.example:5432/app?sslmode=verify-full&sslrootcert=" + root, certOwn, ""},
		{"postgres://u@public.example:5432/app?sslmode=require", certNotVerified, ""},
		{"postgres://u@public.example:5432/app?sslmode=disable", certNotVerified, ""},
	} {
		kind, provider := s.certificateKind(tc.dsn)
		require.Equal(t, tc.kind, kind, tc.dsn)
		require.Equal(t, tc.provider, provider, tc.dsn)
	}

	// A string with no sslmode, as the check reads it: a built-in
	// profile's host is verified by its provider; an operator's pin, a host
	// no profile covers and an explicit mode are as given.
	for _, tc := range []struct {
		dsn      string
		kind     string
		provider string
	}{
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres", certProvider, "supabase"},
		{"postgres://u@x.rds.amazonaws.com:5432/app", certProvider, "aws-rds"},
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=require", certNotVerified, ""},
		{"postgres://u@db.example:5432/app", certNotVerified, ""},
		{"postgres://u@public.example:5432/app", certNotVerified, ""},
	} {
		kind, provider := s.certificateKind(s.verifyByDefault(tc.dsn))
		require.Equal(t, tc.kind, kind, tc.dsn)
		require.Equal(t, tc.provider, provider, tc.dsn)
	}
}

// TestAgentCredentialVerifiesByDefault: the agent's connection string,
// built from the admin string the run uses, keeps the sslmode=verify-full
// a built-in profile's host got by default, so the agent's own connection
// checks the certificate too.
func TestAgentCredentialVerifiesByDefault(t *testing.T) {
	t.Parallel()
	s, err := NewLocal(LocalOptions{
		Backend:    testBackend{},
		ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
		Profiles: trustprofile.BuiltInSet,
	})
	require.NoError(t, err)
	for _, admin := range []string{
		"postgresql://postgres" + ":" + "adminpw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
		"postgres://postgres.abcdefghijklmnopqrst" + ":" + "adminpw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
		"postgres://admin" + ":" + "adminpw@app.abc.eu-west-1.rds.amazonaws.com/app",
	} {
		dsn, err := s.be.AgentConnString(s.verifyByDefault(admin), "basalt_agent_bot", "agentpw")
		require.NoError(t, err, admin)
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		require.Equal(t, "verify-full", u.Query().Get("sslmode"), admin)
		require.False(t, u.Query().Has("sslrootcert"), admin)
	}
}
