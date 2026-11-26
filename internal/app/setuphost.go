package app

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	coretrust "github.com/basaltdbhq/basaltdb/internal/core/trustprofile"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/lib/certroots"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/keyfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setupcli"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/credfiles"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/enginefiles"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// shell is the shell's real host: the adapters, reached through this
// package's own functions.
type shell struct{}

func (shell) Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return pgdial.Connect(ctx, dsn)
}

func (shell) WithCertificateHint(dsn string, err error) error {
	return pgdial.WithCertificateHint(dsn, err)
}

func (shell) CertificateNotVerified(err error) bool { return pgdial.CertificateNotVerified(err) }

func (shell) CurrentTrustProfileSet() *trustprofile.Set { return pgdial.Trust() }

func (shell) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

// setupHost is the setup commands' real host: each method forwards to the
// adapter that does it, and its engine files (by path) are the setup page's
// adapter's (UpsertAgentVault for init --remote).
type setupHost struct{ enginefiles.Files }

func (setupHost) GuardAgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}

func (setupHost) GuardAgentVersion(ctx context.Context, q setup.Querier) (int, error) {
	return guard.AgentVersion(ctx, pgquerier.Of(q))
}

func (setupHost) GuardLatestVersion() int { return guard.LatestVersion() }

func (setupHost) GuardSetupRecorded(ctx context.Context, q setup.Querier, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, pgquerier.Of(q), id)
}

func (setupHost) LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return keyfile.LoadOrCreateKeys(path, now)
}

func (setupHost) TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return trustdir.Set(configPath).For(host)
}

// PinRoots are the system's and the public roots the check of an unknown
// authority reads.
func (setupHost) PinRoots() coretrust.Roots { return certroots.Store{} }

func (setupHost) OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error) {
	return osservice.OpenTrustedDirPort(dir, owner, create)
}

func (setupHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

func (setupHost) OSLookupUID(name string) int { return osservice.LookupUID(name) }

func (setupHost) OSInstallScript(goos, binary string) (string, error) {
	return osservice.InstallScriptFor(goos, binary)
}

func (setupHost) OSRemoveScript(goos string) (string, error) { return osservice.RemoveScript(goos) }

func (setupHost) OSResetScript(goos string) (string, error) { return osservice.ResetScript(goos) }

func (setupHost) OSRestartScript(goos, binary string) (string, error) {
	return osservice.RestartScriptFor(goos, binary)
}

func (setupHost) OSServiceBinary(goos string) string { return osservice.ServiceBinary(goos) }

func (setupHost) OSDefaultUser(goos string) string { return osservice.DefaultUser(goos) }

func (setupHost) OSUnitPath(goos string) string { return osservice.UnitPath(goos) }

func (setupHost) ConnTarget(dsn string) (setup.ConnTarget, error) { return pgdial.ConnTarget(dsn) }

func (setupHost) ServerMessage(err error) (string, bool) { return pgdial.ServerMessage(err) }

func (setupHost) PathCredFiles() setup.CredFiles { return pathCredFiles{} }

func (h setupHost) OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error) {
	return credfiles.OpenRootCredFiles(h, dir, trusted)
}

func (setupHost) RootTrustedOwner(dir string) (int, error) { return credfiles.RootTrustedOwner(dir) }

func (h setupHost) OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error) {
	return credfiles.OpenRootConfigDir(h, dir, trusted)
}

func (h setupHost) RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error) {
	return credfiles.RootEngineKey(h, stateDir, goos, cfg, now, engine.StateDirMode)
}

// probeLogin tries a login with dsn and closes it: the error says how far
// it got (setup.HardenedCredential).
func probeLogin(c *cli.IO) func(context.Context, string) error {
	return func(ctx context.Context, dsn string) error {
		ctx, cancel := context.WithTimeout(ctx, setup.LoginTimeout)
		defer cancel()
		conn, err := c.Dial(ctx, dsn)
		if err != nil {
			return err
		}
		return conn.Close(ctx)
	}
}

// pgErrors is setup.DBErrors on pgx's server errors.
type pgErrors struct{}

func (pgErrors) ServerMessage(err error) (string, bool) { return pgdial.ServerMessage(err) }

// The service install's host (setup.ServiceHost): each method is the
// adapter call it is named after.

func (setupHost) LoadConfigNoFollow(path string) (config.Config, error) {
	return config.LoadNoFollow(path)
}

func (setupHost) LoadEngineConfigAsSelf(path string) (config.Config, error) {
	return cli.LoadEngineConfigAs(shell{}, os.Geteuid(), path)
}

func (setupHost) LockConfigAs(path string, uid int) (config.HeldLock, error) {
	return config.LockConfigAs(path, uid)
}

func (h setupHost) ReadKeptCredential(path, engineUser string) (string, error) {
	return credfiles.ReadKeptCredential(h, path, engineUser)
}

func (h setupHost) UpsertedVault(configPath, engineUser string, s config.Settings, a config.Agent) ([]byte, config.VaultWritten, error) {
	return credfiles.UpsertedVault(h, configPath, engineUser, s, a)
}

func (setupHost) CredentialMissing(path string) bool { return credfiles.CredentialMissing(path) }

func (setupHost) CheckAgentOSUser(osUser, engineUser string) error {
	return setupcli.CheckAgentOSUser(osUser, engineUser)
}

func (setupHost) WithPluginUnits(spec servicespec.Spec, cfg config.Config, warn io.Writer) servicespec.Spec {
	return plugin.ServiceUnits{Files: pluginPorts.Files, TerminalText: cli.TerminalText}.WithPluginUnits(spec, cfg, warn)
}

func (setupHost) InstallUnits(ctx context.Context, spec servicespec.Spec, dryRun bool, out, errw io.Writer) error {
	return osservice.InstallService(ctx, spec, dryRun, out, errw)
}
