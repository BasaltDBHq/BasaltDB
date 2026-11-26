package setup_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// fakeServiceHost records the calls of a service install.
type fakeServiceHost struct {
	calls     []string
	installed servicespec.Spec
}

func (h *fakeServiceHost) OSDefaultUser(string) string { return "basalt" }

func (h *fakeServiceHost) OSLookupUID(string) int {
	h.calls = append(h.calls, "uid")
	return 1
}

func (h *fakeServiceHost) LoadConfigNoFollow(string) (config.Config, error) {
	h.calls = append(h.calls, "load")
	return config.Config{}, os.ErrNotExist
}

func (h *fakeServiceHost) LoadEngineConfigAsSelf(string) (config.Config, error) {
	return config.Config{}, os.ErrNotExist
}

func (h *fakeServiceHost) LockConfigAs(string, int) (config.HeldLock, error) {
	h.calls = append(h.calls, "lock")
	return config.HeldLock{}, errors.New("no lock in a dry run")
}

func (h *fakeServiceHost) ReadKeptCredential(string, string) (string, error) {
	return "", os.ErrNotExist
}

func (h *fakeServiceHost) UpsertedVault(string, string, config.Settings, config.Agent) ([]byte, config.VaultWritten, error) {
	h.calls = append(h.calls, "upsert")
	return nil, config.VaultWritten{}, nil
}
func (h *fakeServiceHost) CredentialMissing(string) bool         { return true }
func (h *fakeServiceHost) CheckAgentOSUser(string, string) error { return nil }
func (h *fakeServiceHost) WithPluginUnits(spec servicespec.Spec, _ config.Config, _ io.Writer) servicespec.Spec {
	return spec
}

func (h *fakeServiceHost) InstallUnits(_ context.Context, spec servicespec.Spec, dryRun bool, _, _ io.Writer) error {
	h.calls = append(h.calls, "install")
	h.installed = spec
	return nil
}

type installUsers struct{}

func (installUsers) Lookup(name string) (*user.User, error) {
	return &user.User{Username: name, Uid: "2000"}, nil
}

func (installUsers) LookupID(uid string) (*user.User, error) {
	return &user.User{Username: "u" + uid, Uid: uid}, nil
}
func (installUsers) GroupIDs(*user.User) ([]string, error) { return nil, nil }
func (installUsers) Self() int                             { return 0 }

// A dry run with --agent takes no lock and writes nothing: the plan names
// the config and the credential, with no contents and no memory limit.
func TestServiceInstallDryRunTakesNoLock(t *testing.T) {
	t.Parallel()
	h := &fakeServiceHost{}
	var out, errw bytes.Buffer
	err := setup.ServiceInstaller{Host: h, Users: installUsers{}}.Install(context.Background(), setup.ServiceInstall{
		GOOS: "linux", Binary: "/usr/local/bin/basalt", ConfigPath: "/etc/basalt/engine.json", User: "basalt",
		DryRun: true, CredentialStdin: true,
		Agent: setup.AgentInstall{Name: "bot", OSUser: "bot", PersonUIDs: []uint32{4242}},
	}, strings.NewReader("postgres"+"://agent:pw@h/db\n"), &out, &errw)
	require.NoError(t, err)
	require.Equal(t, []string{"load", "load", "install"}, h.calls, "no lock, no upsert, no hand-off")
	require.Len(t, h.installed.Files, 2)
	require.Empty(t, h.installed.Files[0].Content)
	require.Zero(t, h.installed.MemoryMB)
}

// SUDO_UID that is no uid is refused before anything is read from stdin or
// locked.
func TestServiceInstallRefusesABadSudoUID(t *testing.T) {
	t.Parallel()
	h := &fakeServiceHost{}
	err := setup.ServiceInstaller{Host: h, Users: installUsers{}}.Install(context.Background(), setup.ServiceInstall{
		GOOS: "linux", ConfigPath: "/etc/basalt/engine.json", User: "basalt", SudoUID: "x",
		Agent: setup.AgentInstall{Name: "bot", OSUser: "bot"},
	}, strings.NewReader(""), io.Discard, io.Discard)
	require.ErrorContains(t, err, setup.EnvSudoUID+": ")
	require.Equal(t, []string{"load"}, h.calls)
}
