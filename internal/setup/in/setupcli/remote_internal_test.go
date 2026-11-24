//go:build unix

package setupcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
)

// releasePage is where the person installs basalt on their own computer.
const releasePage = "https://github.com/BasaltDBHq/BasaltDB/releases"

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
	adapters := map[string]func(t *testing.T, dir string) setup.CredFiles{
		"path": func(*testing.T, string) setup.CredFiles { return credfiles.PathCredFiles{} },
		"root": func(t *testing.T, dir string) setup.CredFiles {
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
				require.NoError(t, config.WriteFile(credFile+setup.PendingSuffix, []byte("postgres://bt_agent_bot:new@db.example.com:5432/app\n")))
				r := &remoteInit{credFile: credFile, files: open(t, dir)}
				pending, err := setup.ReadCredentialIfAny(r.files, credFile+setup.PendingSuffix)
				require.NoError(t, err)

				apply(t, credFile+setup.PendingSuffix)
				err = r.promote(pending)
				require.ErrorContains(t, err, "changed while basalt init ran; nothing changed, run it again")
				require.FileExists(t, credFile+setup.PendingSuffix)
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
	require.NoError(t, config.WriteFile(credFile+setup.PendingSuffix, []byte("postgres://bt_agent_bot:new@db.example.com:5432/app\n")))
	files, err := credfiles.OpenRootCredFiles(filesHost{}, dir, os.Geteuid())
	require.NoError(t, err)
	t.Cleanup(files.Close)
	r := &remoteInit{credFile: credFile, files: files}
	pending, err := setup.ReadCredentialIfAny(r.files, credFile+setup.PendingSuffix)
	require.NoError(t, err)

	elsewhere := filepath.Join(dir, "elsewhere.url")
	require.NoError(t, os.Rename(credFile+setup.PendingSuffix, elsewhere))
	require.NoError(t, os.Symlink(elsewhere, credFile+setup.PendingSuffix))
	_, want := files.Stat(credFile + setup.PendingSuffix)
	require.Error(t, want)
	err = r.promote(pending)
	require.Equal(t, want.Error(), err.Error(), "the open error itself")
	require.NotContains(t, err.Error(), "changed while basalt init ran")
	got, err := os.ReadFile(credFile)
	require.NoError(t, err)
	require.Equal(t, old, string(got), "the credential file is unchanged")
}

func TestSetupPersonMessageFitsForTheLongestName(t *testing.T) {
	t.Parallel()
	name := ""
	for n := 1; n < 100; n++ {
		if candidate := strings.Repeat("a", n); config.ValidAgentName(candidate) {
			name = candidate
		}
	}
	require.GreaterOrEqual(t, len(name), 50)
	pm := setupPersonMessage(name, "3f9a 21c0 7d44 e1b2 90ac")
	withoutURL := strings.Replace(pm, releasePage+"\n", "", 1)
	require.LessOrEqual(t, utf8.RuneCountInString(withoutURL), guidance.MaxPersonMessageLength, pm)
	require.Equal(t, 1, strings.Count(pm, name), "the agent is named once")
}

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
		c: &cli.IO{Stderr: &stderr}, configDir: d, osUser: "bot", credFile: filepath.Join(dir, "agents", "bot.url"),
		f:        setup.RemoteFlags{Agent: "bot", ConfigPath: filepath.Join(dir, "engine.json")},
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
