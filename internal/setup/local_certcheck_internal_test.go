package setup

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// credBackend is testBackend with the agent's credential dsn.
type credBackend struct {
	testBackend
	dsn   string
	plain bool
}

func (b credBackend) ReadCredential(string) (string, error) { return b.dsn, nil }

// ConnCertificate is the login's TLS: on unless plain.
func (b credBackend) ConnCertificate(_ Conn, kind, _ string) (string, string) {
	if b.plain {
		return certificateNone, ""
	}
	return kind, ""
}

// TestUncheckedCredential: an agent credential below verify-full (none is
// prefer) is NOT_CHECKED with TLS on its login and NOT_ENCRYPTED without,
// naming the provider whose built-in roots cover its host; verify-full and
// a credential with its own roots are neither.
func TestUncheckedCredential(t *testing.T) {
	t.Parallel()
	at := func(rest string) string { return "postgresql://u" + ":" + "pw@" + rest }
	supa := at("db.abcdefghijklmnopqrst.supabase.co:5432/postgres")
	for _, tc := range []struct {
		dsn, mode, provider string
		ok                  bool
	}{
		{supa + "?sslmode=require", "require", "Supabase", true},
		{supa + "?sslmode=verify-ca", "verify-ca", "Supabase", true},
		{at("db.example.com:6543/app"), "prefer", "", true},
		{supa + "?sslmode=verify-full", "", "", false},
		{supa + "?sslmode=verify-ca&sslrootcert=/x/root.crt", "", "", false},
	} {
		s, err := NewLocal(LocalOptions{
			Backend:    credBackend{dsn: tc.dsn},
			ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
			Profiles: trustprofile.BuiltInSet,
		})
		require.NoError(t, err)
		uc, ok := s.uncheckedCredential(config.Agent{})
		require.Equal(t, tc.ok, ok, tc.dsn)
		require.Equal(t, tc.mode, uc.mode, tc.dsn)
		require.Equal(t, tc.provider, uc.provider, tc.dsn)
		var out DoctorAnswer
		out.Certificate.State = StateOK
		s.certificateNotChecked(nil, config.Agent{}, &out)
		if tc.ok {
			require.Equal(t, DoctorCertificate{State: StateNotChecked, Host: uc.host, Port: uc.port, SSLMode: tc.mode, Provider: tc.provider}, out.Certificate, tc.dsn)
		} else {
			require.Equal(t, StateOK, out.Certificate.State, tc.dsn)
		}
	}

	// No TLS on the login: disable, allow, or prefer that fell back.
	for _, tc := range []struct{ dsn, mode, provider string }{
		{supa + "?sslmode=disable", "disable", "Supabase"},
		{supa + "?sslmode=allow", "allow", "Supabase"},
		{at("db.example.com:5432/app"), "prefer", ""},
	} {
		s, err := NewLocal(LocalOptions{
			Backend:    credBackend{dsn: tc.dsn, plain: true},
			ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
			Profiles: trustprofile.BuiltInSet,
		})
		require.NoError(t, err)
		out := DoctorAnswer{Certificate: DoctorCertificate{State: StateOK}}
		s.certificateNotChecked(nil, config.Agent{}, &out)
		require.Equal(t, StateNotEncrypted, out.Certificate.State, tc.dsn)
		require.Equal(t, tc.mode, out.Certificate.SSLMode, tc.dsn)
		require.Equal(t, tc.provider, out.Certificate.Provider, tc.dsn)
	}
	for _, h := range []string{"localhost:5432", "127.0.0.1:5432", "[::1]:5432"} {
		s, err := NewLocal(LocalOptions{
			Backend:    credBackend{dsn: at(h + "/app?sslmode=disable"), plain: true},
			ConfigPath: filepath.Join(t.TempDir(), "engine.json"), Origin: "http://localhost:8787",
			Profiles: trustprofile.BuiltInSet,
		})
		require.NoError(t, err)
		out := DoctorAnswer{Certificate: DoctorCertificate{State: StateOK}}
		s.certificateNotChecked(nil, config.Agent{}, &out)
		require.Equal(t, StateOK, out.Certificate.State, "a loopback host is not warned: %s", h)
	}
}
