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
	dsn string
}

func (b credBackend) ReadCredential(string) (string, error) { return b.dsn, nil }

// TestUncheckedCredential: an agent credential is NOT_CHECKED when it is
// encrypted below verify-full (none is prefer), naming the provider whose
// built-in roots cover its host; verify-full, disable and allow are not.
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
		{supa + "?sslmode=disable", "", "", false},
		{supa + "?sslmode=allow", "", "", false},
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
		s.certificateNotChecked(config.Agent{}, &out)
		if tc.ok {
			require.Equal(t, DoctorCertificate{State: StateNotChecked, Host: uc.host, Port: uc.port, SSLMode: tc.mode, Provider: tc.provider}, out.Certificate, tc.dsn)
		} else {
			require.Equal(t, StateOK, out.Certificate.State, tc.dsn)
		}
	}
}
