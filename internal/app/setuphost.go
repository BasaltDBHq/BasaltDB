package app

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup"
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

// setupHost is basalt init --remote's real host: the adapters, reached
// through this package's own functions.
type setupHost struct{}

func (setupHost) GuardAgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}

func (setupHost) GuardAgentVersion(ctx context.Context, q pgquerier.Querier) (int, error) {
	return guard.AgentVersion(ctx, q)
}

func (setupHost) GuardLatestVersion() int { return guard.LatestVersion() }

func (setupHost) GuardSetupRecorded(ctx context.Context, q pgquerier.Querier, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, q, id)
}

func (setupHost) LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return loadOrCreateEngineKeys(path, now)
}

func (setupHost) TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return trustdir.Set(configPath).For(host)
}

func (setupHost) OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error) {
	d, err := osservice.OpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (setupHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return osservice.OpenTrustedFile(path, owner)
}

func (setupHost) OSLookupUID(name string) int { return osservice.LookupUID(name) }

func (setupHost) OSInstallScript(goos, binary string) (string, error) {
	src, err := osservice.ReadSource(binary)
	if err != nil {
		return "", err
	}
	return osservice.InstallScript(goos, src)
}

func (setupHost) OSRemoveScript(goos string) (string, error) { return osservice.RemoveScript(goos) }

func (setupHost) OSResetScript(goos string) (string, error) { return osservice.ResetScript(goos) }

func (setupHost) OSRestartScript(goos, binary string) (string, error) {
	src, err := osservice.ReadSource(binary)
	if err != nil {
		return "", err
	}
	return osservice.RestartScript(goos, src)
}

func (setupHost) OSServiceBinary(goos string) string { return osservice.ServiceBinary(goos) }

func (setupHost) OSDefaultUser(goos string) string { return osservice.DefaultUser(goos) }

func (setupHost) OSUnitPath(goos string) string { return osservice.UnitPath(goos) }

func (setupHost) ConnTarget(dsn string) (setup.ConnTarget, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setup.ConnTarget{}, err
	}
	return setup.ConnTarget{Host: cfg.Host, Port: int(cfg.Port), SystemRoots: cfg.TLSConfig != nil && cfg.TLSConfig.RootCAs == nil}, nil
}

func (setupHost) ServerMessage(err error) (string, bool) { return pgErrors{}.ServerMessage(err) }

func (setupHost) PathCredFiles() setup.CredFiles { return pathCredFiles{} }

func (h setupHost) OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error) {
	return openRootCredFiles(h, dir, trusted)
}

func (setupHost) RootTrustedOwner(dir string) (int, error) { return rootTrustedOwner(dir) }

func (h setupHost) OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error) {
	d, err := openRootConfigDir(h, dir, trusted)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (h setupHost) RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error) {
	d, _ := cfg.(*rootConfigDir)
	return rootEngineKey(h, stateDir, goos, d, now)
}

// setupFilesHost is how setup reaches the files root reads and writes for
// the engine's user: directories and files opened from / without following
// a link anyone but root or their owner controls, and OS user ids.
type setupFilesHost interface {
	// OSOpenTrustedDir opens dir for root, refusing a directory on the way
	// that someone other than root or owner could swap; create makes it
	// when missing.
	OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error)
	// OSOpenTrustedFile opens path read-only for root: its directory as
	// OSOpenTrustedDir does, the file itself never through a symlink.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
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

func (pgErrors) ServerMessage(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", false
	}
	return pg.Message, true
}
