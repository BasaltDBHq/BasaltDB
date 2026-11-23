package main

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"

	"github.com/jackc/pgx/v5"

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
