package localsetup

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
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
	s, err := New(Options{
		Backend:    setupbackend.Backend{},
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
		kind     setup.CertificateKind
		provider string
	}{
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=verify-full", setup.CertificateProvider, "supabase"},
		{"postgres://u@x.rds.amazonaws.com:5432/app?sslmode=verify-full", setup.CertificateProvider, "aws-rds"},
		{"postgres://u@db.example:5432/app?sslmode=verify-full", setup.CertificateOwn, ""},
		{"postgres://u@public.example:5432/app?sslmode=verify-full", setup.CertificatePublic, ""},
		{"postgres://u@public.example:5432/app?sslmode=verify-full&sslrootcert=" + root, setup.CertificateOwn, ""},
		{"postgres://u@public.example:5432/app?sslmode=require", setup.CertificateNotVerified, ""},
		{"postgres://u@public.example:5432/app?sslmode=disable", setup.CertificateNotVerified, ""},
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
		kind     setup.CertificateKind
		provider string
	}{
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres", setup.CertificateProvider, "supabase"},
		{"postgres://u@x.rds.amazonaws.com:5432/app", setup.CertificateProvider, "aws-rds"},
		{"postgres://u@db.abcdefghijklmnopqrst.supabase.co:5432/postgres?sslmode=require", setup.CertificateNotVerified, ""},
		{"postgres://u@db.example:5432/app", setup.CertificateNotVerified, ""},
		{"postgres://u@public.example:5432/app", setup.CertificateNotVerified, ""},
	} {
		kind, provider := s.certificateKind(s.verifyByDefault(tc.dsn))
		require.Equal(t, tc.kind, kind, tc.dsn)
		require.Equal(t, tc.provider, provider, tc.dsn)
	}
}
