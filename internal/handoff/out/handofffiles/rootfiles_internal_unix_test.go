//go:build unix

package handofffiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/testkit/configtest"
)

// pg starts a test connection string; built so no secret scanner reads one
// as a committed credential.
const pg = "postgres" + "://"

// rootLayout is a config directory with engine.json and agents/bot.url.
func rootLayout(t *testing.T) (cfgPath, credFile string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	dir := filepath.Join(root, "basalt")
	cfgPath, credFile = filepath.Join(dir, "engine.json"), filepath.Join(dir, "agents", "bot.url")
	require.NoError(t, config.WriteFile(credFile, []byte(pg+"bt_agent_bot:old@db:5432/app\n")))
	require.NoError(t, configtest.UpsertAgent(cfgPath, config.Settings{SocketDir: "/run/basalt"}, config.Agent{
		Name: "bot", OSUser: "bot", Store: config.PostgresStore(credFile),
	}))
	return cfgPath, credFile
}

// A root engine connects with the credential it reads, and pgx reads files
// for the caller from some parameters: a credential or .pending the owner
// of agents/ wrote must pass the allowlist basalt init --remote applies as
// root (pgdial.CheckForeignDSN). Root's own files are taken as they are.
func TestRootEngineChecksTheOwnersCredential(t *testing.T) {
	t.Parallel()
	cfgPath, credFile := rootLayout(t)
	r, err := OpenRootFiles(cfgPath, credFile)
	require.NoError(t, err)
	defer r.Close()
	files := r
	require.Equal(t, os.Geteuid(), r.self)

	const ok1 = pg + "bt_agent_bot:pw@db.example.com:5432/app?sslmode=verify-full&channel_binding=require"
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{dsn: ok1, ok: true},
		{dsn: pg + "bt_agent_bot:pw@db.example.com:5432/app?sslrootcert=/root/ca.pem"},
		{dsn: pg + "bt_agent_bot:pw@db.example.com:5432/app?passfile=/root/.pgpass"},
		{dsn: "postgres://bt_agent_bot@db.example.com:5432/app"},
		{dsn: "host=db.example.com user=bt_agent_bot password=pw sslkey=/root/k"},
	} {
		for _, name := range []string{credFile, credFile + config.PendingSuffix} {
			require.NoError(t, os.WriteFile(name, []byte(tc.dsn+"\n"), config.FileMode))
		}
		read := func() []error {
			_, err := files.ReadCredential()
			_, _, perr := files.ReadPending(4096)
			return []error{err, perr}
		}
		r.self = os.Geteuid() // root wrote them: taken as they are
		for _, err := range read() {
			require.NoError(t, err, tc.dsn)
		}
		r.self = os.Geteuid() + 1 // the owner of agents/ wrote them
		for _, err := range read() {
			if tc.ok {
				require.NoError(t, err, tc.dsn)
				continue
			}
			require.ErrorIs(t, err, pgdial.ErrForeignDSN, tc.dsn)
			require.ErrorContains(t, err, "as root, basalt engine takes from it only")
			require.NotContains(t, err.Error(), ":pw", "the password is not echoed")
		}
	}
}
