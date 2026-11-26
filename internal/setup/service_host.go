package setup

import (
	"context"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// ServiceHost is what basalt service install reaches outside the setup
// service. Every method is the adapter call it is named after.
type ServiceHost interface {
	// OSDefaultUser is the engine's default OS user on goos.
	OSDefaultUser(goos string) string
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
	// LoadConfigNoFollow reads the engine config at path, refusing a link
	// at it (config.LoadNoFollow).
	LoadConfigNoFollow(path string) (config.Config, error)
	// LoadEngineConfigAsSelf is the hardened read of the engine config as
	// this process's user (cli.LoadEngineConfigAs).
	LoadEngineConfigAsSelf(path string) (config.Config, error)
	// LockConfigAs takes the config lock, its file given to uid
	// (config.LockConfigAs).
	LockConfigAs(path string, uid int) (config.HeldLock, error)
	// ReadKeptCredential reads a credential file the engine's user keeps
	// (credfiles.ReadKeptCredential).
	ReadKeptCredential(path, engineUser string) (string, error)
	// UpsertedVault is the config at configPath, opened as root reads the
	// engine user's file, with s and a upserted (config.UpsertedVault).
	UpsertedVault(configPath, engineUser string, s config.Settings, a config.Agent) ([]byte, config.VaultWritten, error)
	// CredentialMissing reports whether no file is at path, not following
	// a link.
	CredentialMissing(path string) bool
	// CheckAgentOSUser refuses an agent OS user that is the engine's own or
	// shares a group with it.
	CheckAgentOSUser(osUser, engineUser string) error
	// WithPluginUnits is spec with cfg's plugin units, a line on warn for
	// each entry left as it is.
	WithPluginUnits(spec servicespec.Spec, cfg config.Config, warn io.Writer) servicespec.Spec
	// InstallUnits plans and applies the service install of spec (printing
	// the steps only for dryRun), the steps' output on out and errw.
	InstallUnits(ctx context.Context, spec servicespec.Spec, dryRun bool, out, errw io.Writer) error
}
