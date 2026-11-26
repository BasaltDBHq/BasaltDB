//go:build unix

package setup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
)

// filesHost opens trusted directories as the real machine does.
type filesHost struct{}

func (filesHost) OSOpenTrustedDir(dir string, owner int, create bool) (credfiles.TrustedDir, error) {
	d, err := osservice.OpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (filesHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

func (filesHost) OSLookupUID(name string) int { return osservice.LookupUID(name) }

// promote moves .pending only while its path names the file read, a
// regular file with one link: one replaced, or given a second hard link,
// since it was read is left in place, by path and through the directory
// root opens.
func TestInitRemotePromoteRefusesAChangedPending(t *testing.T) {
	t.Parallel()
	adapters := map[string]func(t *testing.T, dir string) CredFiles{
		"path": func(*testing.T, string) CredFiles { return credfiles.PathCredFiles{} },
		"root": func(t *testing.T, dir string) CredFiles {
			t.Helper()
			files, err := credfiles.OpenRootCredFiles(filesHost{}, dir, os.Geteuid())
			require.NoError(t, err)
			t.Cleanup(files.Close)
			return files
		},
	}
	changes := map[string]func(t *testing.T, path string){
		"replaced": func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, config.WriteFile(path, []byte("postgres://bt_agent_bot:planted@db.example.com:5432/app\n")))
		},
		"hard linked": func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, os.Link(path, path+".link"))
		},
	}
	for adapter, open := range adapters {
		for change, apply := range changes {
			t.Run(adapter+" "+change, func(t *testing.T) {
				t.Parallel()
				dir, err := filepath.EvalSymlinks(t.TempDir())
				require.NoError(t, err)
				credFile := filepath.Join(dir, "bot.url")
				const old = "postgres://bt_agent_bot:old@db.example.com:5432/app\n"
				require.NoError(t, config.WriteFile(credFile, []byte(old)))
				require.NoError(t, config.WriteFile(credFile+config.PendingSuffix, []byte("postgres://bt_agent_bot:new@db.example.com:5432/app\n")))
				r := &remoteInit{credFile: credFile, files: open(t, dir)}
				pending, err := ReadCredentialIfAny(r.files, credFile+config.PendingSuffix)
				require.NoError(t, err)

				apply(t, credFile+config.PendingSuffix)
				err = r.promote(pending)
				require.ErrorContains(t, err, "changed while basalt init ran; nothing changed, run it again")
				require.FileExists(t, credFile+config.PendingSuffix)
				got, err := os.ReadFile(credFile)
				require.NoError(t, err)
				require.Equal(t, old, string(got), "the credential file is unchanged")
				require.False(t, r.credExists)
			})
		}
	}
}

// An error reaching .pending before the move is returned as it is, not as
// a changed file: as root, a .pending swapped for a symlink fails to open
// (the directory is reached without following links), and nothing moves.
func TestInitRemotePromoteReturnsTheErrorReachingPending(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	credFile := filepath.Join(dir, "bot.url")
	const old = "postgres://bt_agent_bot:old@db.example.com:5432/app\n"
	require.NoError(t, config.WriteFile(credFile, []byte(old)))
	require.NoError(t, config.WriteFile(credFile+config.PendingSuffix, []byte("postgres://bt_agent_bot:new@db.example.com:5432/app\n")))
	files, err := credfiles.OpenRootCredFiles(filesHost{}, dir, os.Geteuid())
	require.NoError(t, err)
	t.Cleanup(files.Close)
	r := &remoteInit{credFile: credFile, files: files}
	pending, err := ReadCredentialIfAny(r.files, credFile+config.PendingSuffix)
	require.NoError(t, err)

	elsewhere := filepath.Join(dir, "elsewhere.url")
	require.NoError(t, os.Rename(credFile+config.PendingSuffix, elsewhere))
	require.NoError(t, os.Symlink(elsewhere, credFile+config.PendingSuffix))
	_, want := files.Stat(credFile + config.PendingSuffix)
	require.Error(t, want)
	err = r.promote(pending)
	require.Equal(t, want.Error(), err.Error(), "the open error itself")
	require.NotContains(t, err.Error(), "changed while basalt init ran")
	got, err := os.ReadFile(credFile)
	require.NoError(t, err)
	require.Equal(t, old, string(got), "the credential file is unchanged")
}

// stderrEnv is a RemoteEnv that takes the notes only: any other call
// panics on the nil RemoteEnv.
type stderrEnv struct {
	RemoteEnv
	w io.Writer
}

func (e stderrEnv) Stderr() io.Writer { return e.w }

// fakeConfigDir is a RootConfigDir that records what is upserted.
type fakeConfigDir struct {
	names    []string
	settings []config.Settings
	agents   []config.Agent
	closed   bool
}

func (d *fakeConfigDir) Upsert(name string, s config.Settings, a config.Agent) (config.VaultWritten, error) {
	d.names = append(d.names, name)
	d.settings = append(d.settings, s)
	d.agents = append(d.agents, a)
	return config.VaultWritten{}, nil
}

func (d *fakeConfigDir) Close() { d.closed = true }

// As root, writeConfig writes engine.json through the config directory
// paths opened, by its file name there, and never by path.
func TestRootWriteConfigUsesTheOpenedConfigDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	d := &fakeConfigDir{}
	var stderr bytes.Buffer
	r := &remoteInit{
		env: stderrEnv{w: &stderr}, configDir: d, osUser: "bot", credFile: filepath.Join(dir, "agents", "bot.url"),
		f:        RemoteFlags{Agent: "bot", ConfigPath: filepath.Join(dir, "engine.json")},
		settings: config.Settings{SocketDir: "/run/basalt"},
	}
	require.NoError(t, r.writeConfig(nil))
	require.Equal(t, []string{"engine.json"}, d.names)
	require.Len(t, d.agents, 1)
	require.Equal(t, "bot", d.agents[0].Name)
	require.Equal(t, "bot", d.agents[0].OSUser)
	require.Equal(t, filepath.Join(dir, "agents", "bot.url"), d.agents[0].Store.CredentialFile)
	require.Equal(t, "/run/basalt", d.settings[0].SocketDir)
	require.NoFileExists(t, filepath.Join(dir, "engine.json"), "nothing is written by path")
}
