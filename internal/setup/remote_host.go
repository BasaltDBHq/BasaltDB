package setup

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// RemoteHost is what basalt init --remote reaches outside the CLI: the guard's
// versions, records and agent connection string, the engine's keys, the
// trust profiles next to the config, the database's server errors, and the
// credential files and config directory, which root opens without following
// a link anyone but root or the file's owner controls.
type RemoteHost interface {
	DBErrors
	// TrustProfileFor is the profile in the trust.d next to the config at
	// configPath that names host, or nil.
	TrustProfileFor(configPath, host string) *trustprofile.Profile
	// ConnTarget is the host and port a connection string names, and whether
	// its TLS check uses the system's roots (TLS on, no root certificate
	// given); the error is the driver's own.
	ConnTarget(dsn string) (ConnTarget, error)
	// GuardAgentConnString is adminURL with the agent's role and password.
	GuardAgentConnString(adminURL, role, password string) (string, error)
	// GuardAgentVersion is the guard version q's database has, 0 when none;
	// q is the agent's login, whose Pgx method gives the driver's connection.
	GuardAgentVersion(ctx context.Context, q Querier) (int, error)
	// GuardLatestVersion is the guard version this binary installs.
	GuardLatestVersion() int
	// GuardSetupRecorded reports whether the setup with id is recorded.
	GuardSetupRecorded(ctx context.Context, q Querier, id uuid.UUID) (bool, error)
	// LoadOrCreateEngineKeys reads the engine's keys at path, making them
	// when there are none.
	LoadOrCreateEngineKeys(path string, now func() time.Time) (*channel.EngineKeys, error)
	// PathCredFiles reaches the credential files by path: init --remote not
	// as root, in the user's own directories.
	PathCredFiles() CredFiles
	// OpenRootCredFiles opens dir, the agents directory, as root, making it
	// (and the config directory) when missing. Every directory on the way
	// must be owned by root or trusted, and no link is followed. Reads
	// through it check the string another user wrote there.
	OpenRootCredFiles(dir string, trusted int) (CredFiles, error)
	// RootTrustedOwner is the owner root trusts on the way to the config
	// directory dir: dir's, or, when it does not exist yet, that of the
	// nearest directory above it that does.
	RootTrustedOwner(dir string) (int, error)
	// OpenRootConfigDir opens dir, the config directory, as root, making it
	// when missing; engine.json is then locked, read and written relative
	// to it, checked as the hardened read checks it.
	OpenRootConfigDir(dir string, trusted int) (RootConfigDir, error)
	// RootEngineKey is the engine's public key for a root init --remote:
	// the key file in stateDir read or, when there is none, created relative
	// to the state directory opened without following a link anyone but
	// root controls, owned by the config directory's owner.
	RootEngineKey(stateDir, goos string, cfg RootConfigDir, now func() time.Time) ([]byte, error)
}
