package main

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/setup"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// appShell is the shell's real host: the adapters, reached through app.
type appShell struct{}

func (appShell) Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return app.Connect(ctx, dsn)
}

func (appShell) WithCertificateHint(dsn string, err error) error {
	return app.WithCertificateHint(dsn, err)
}

func (appShell) CertificateNotVerified(err error) bool { return app.CertificateNotVerified(err) }

func (appShell) CurrentTrustProfileSet() *trustprofile.Set { return app.CurrentTrustProfileSet() }

func (appShell) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return app.OSOpenTrustedFile(path, owner)
}

// appSetupHost is basalt init --remote's real host: the adapters, reached
// through app.
type appSetupHost struct{}

func (appSetupHost) GuardAgentConnString(adminURL, role, password string) (string, error) {
	return app.GuardAgentConnString(adminURL, role, password)
}

func (appSetupHost) GuardAgentVersion(ctx context.Context, q pgquerier.Querier) (int, error) {
	return app.GuardAgentVersion(ctx, q)
}

func (appSetupHost) GuardLatestVersion() int { return app.GuardLatestVersion() }

func (appSetupHost) GuardSetupRecorded(ctx context.Context, q pgquerier.Querier, id uuid.UUID) (bool, error) {
	return app.GuardSetupRecorded(ctx, q, id)
}

func (appSetupHost) LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error) {
	return app.LoadOrCreateEngineKeys(path, now)
}

func (appSetupHost) TrustProfileFor(configPath, host string) *trustprofile.Profile {
	return app.TrustProfileFor(configPath, host)
}

func (appSetupHost) OSOpenTrustedDir(dir string, owner int, create bool) (trustedDir, error) {
	d, err := app.OSOpenTrustedDir(dir, owner, create)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (appSetupHost) OSOpenTrustedFile(path string, owner int) (*os.File, error) {
	return app.OSOpenTrustedFile(path, owner)
}

func (appSetupHost) OSLookupUID(name string) int { return app.OSLookupUID(name) }

func (appSetupHost) OSInstallScript(goos, binary string) (string, error) {
	return app.OSInstallScript(goos, binary)
}

func (appSetupHost) OSRemoveScript(goos string) (string, error) { return app.OSRemoveScript(goos) }

func (appSetupHost) OSResetScript(goos string) (string, error) { return app.OSResetScript(goos) }

func (appSetupHost) OSDefaultUser(goos string) string { return app.OSDefaultUser(goos) }

func (appSetupHost) OSUnitPath(goos string) string { return app.OSUnitPath(goos) }

func (appSetupHost) ConnTarget(dsn string) (setup.ConnTarget, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setup.ConnTarget{}, err
	}
	return setup.ConnTarget{Host: cfg.Host, Port: int(cfg.Port), SystemRoots: cfg.TLSConfig != nil && cfg.TLSConfig.RootCAs == nil}, nil
}

func (appSetupHost) ServerMessage(err error) (string, bool) { return pgErrors{}.ServerMessage(err) }

func (appSetupHost) PathCredFiles() setup.CredFiles { return app.PathCredFiles{} }

func (h appSetupHost) OpenRootCredFiles(dir string, trusted int) (setup.CredFiles, error) {
	return openRootCredFiles(h, dir, trusted)
}

func (appSetupHost) RootTrustedOwner(dir string) (int, error) { return rootTrustedOwner(dir) }

func (h appSetupHost) OpenRootConfigDir(dir string, trusted int) (setup.RootConfigDir, error) {
	d, err := openRootConfigDir(h, dir, trusted)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (h appSetupHost) RootEngineKey(stateDir, goos string, cfg setup.RootConfigDir, now func() time.Time) ([]byte, error) {
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

// trustedDir is a directory opened by OSOpenTrustedDir: files in it are
// reached relative to its descriptor, never by path. It is the credential
// files' own (app.TrustedDir), so a setupFilesHost reaches them too.
type trustedDir = app.TrustedDir
