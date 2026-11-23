package setupbackend_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
)

// The setup page reads an agent's credential as root, so the read and the
// foreign-string check are one step: a string that makes the driver read a
// file is refused with ErrForeignCredential, and a read that fails returns
// config.ReadCredential's own error.
func TestReadCredentialRefusesAForeignString(t *testing.T) {
	t.Parallel()
	// Split so no scanner takes the fixtures for real connection strings.
	const clean = "postgres://bot" + ":pw@db.example.com:5432/app?sslmode=verify-full"
	for _, tc := range []struct {
		name    string
		dsn     string
		refused bool
	}{
		{name: "clean", dsn: clean},
		{name: "passfile", dsn: clean + "&passfile=/root/.pgpass", refused: true},
		{name: "sslrootcert", dsn: clean + "&sslrootcert=/etc/shadow", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "credential")
			require.NoError(t, os.WriteFile(path, []byte(tc.dsn+"\n"), 0o600))
			got, err := setupbackend.Backend{}.ReadCredential(path)
			if tc.refused {
				require.ErrorIs(t, err, setuprun.ErrForeignCredential)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.dsn, got)
		})
	}
}

func TestReadCredentialPassesAReadErrorThrough(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const dsn = "postgres://bot" + ":pw@db.example.com/app"
	open := filepath.Join(dir, "open")
	require.NoError(t, os.WriteFile(open, []byte(dsn), 0o600))
	require.NoError(t, os.Chmod(open, 0o644))
	for _, path := range []string{filepath.Join(dir, "missing"), open} {
		_, want := config.ReadCredential(path)
		require.Error(t, want)
		got, err := setupbackend.Backend{}.ReadCredential(path)
		require.Empty(t, got)
		require.Equal(t, want, err, path)
		require.NotErrorIs(t, err, setuprun.ErrForeignCredential, path)
	}
}
