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
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Shell is the shell's real host: the adapters, reached through this
// package's own functions.
type Shell struct{}

func (Shell) Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return Connect(ctx, dsn)
}

func (Shell) WithCertificateHint(dsn string, err error) error {
	return WithCertificateHint(dsn, err)
}

func (Shell) CertificateNotVerified(err error) bool { return CertificateNotVerified(err) }

func (Shell) CurrentTrustProfileSet() *trustprofile.Set { return CurrentTrustProfileSet() }

func (Shell) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return OSOpenTrustedFile(path, owner)
}

// SetupHost is basalt init --remote's real host: the adapters, reached
// through this package's own functions.
type SetupHost struct{}

func (SetupHost) GuardAgentConnString(adminURL, role, password string) (string, error) {
	return GuardAgentConnString(adminURL, role, password)
}

func (SetupHost) GuardAgentVersion(ctx context.Context, q pgquerier.Querier) (int, error) {
	return GuardAgentVersion(ctx, q)
}

func (SetupHost) GuardLatestVersion() int { return GuardLatestVersion() }

func (SetupHost) GuardSetupRecorded(ctx context.Context, q pgquerier.Querier, id uuid.UUID) (bool, error) {
	return GuardSetupRecorded(ctx, q, id)
}

func (SetupHost) LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return LoadOrCreateEngineKeys(path, now)
}

func (SetupHost) TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return TrustProfileFor(configPath, host)
}

func (SetupHost) OSOpenTrustedDir(dir string, owner int, create bool) (TrustedDir, error) {
	d, err := OSOpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (SetupHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return OSOpenTrustedFile(path, owner)
}

func (SetupHost) OSLookupUID(name string) int { return OSLookupUID(name) }

func (SetupHost) OSInstallScript(goos, binary string) (string, error) {
	return OSInstallScript(goos, binary)
}

func (SetupHost) OSRemoveScript(goos string) (string, error) { return OSRemoveScript(goos) }

func (SetupHost) OSResetScript(goos string) (string, error) { return OSResetScript(goos) }

func (SetupHost) OSDefaultUser(goos string) string { return OSDefaultUser(goos) }

func (SetupHost) OSUnitPath(goos string) string { return OSUnitPath(goos) }

func (SetupHost) ConnTarget(dsn string) (setup.ConnTarget, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setup.ConnTarget{}, err
	}
	return setup.ConnTarget{Host: cfg.Host, Port: int(cfg.Port), SystemRoots: cfg.TLSConfig != nil && cfg.TLSConfig.RootCAs == nil}, nil
}

func (SetupHost) ServerMessage(err error) (string, bool) { return pgErrors{}.ServerMessage(err) }

func (SetupHost) PathCredFiles() setup.CredFiles { return PathCredFiles{} }

func (h SetupHost) OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error) {
	return openRootCredFiles(h, dir, trusted)
}

func (SetupHost) RootTrustedOwner(dir string) (int, error) { return rootTrustedOwner(dir) }

func (h SetupHost) OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error) {
	d, err := openRootConfigDir(h, dir, trusted)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (h SetupHost) RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error) {
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
	OSOpenTrustedDir(dir string, owner int, create bool) (TrustedDir, error)
	// OSOpenTrustedFile opens path read-only for root: its directory as
	// OSOpenTrustedDir does, the file itself never through a symlink.
	OSOpenTrustedFile(path string, owner int) (*os.File, error)
	// OSLookupUID is the uid of the OS user name, or -1 when there is no
	// such user.
	OSLookupUID(name string) int
}

// ProbeLogin tries a login with dsn and closes it: the error says how far
// it got (setup.HardenedCredential).
func ProbeLogin(c *cli.IO) func(context.Context, string) error {
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
