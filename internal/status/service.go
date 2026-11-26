package status

import (
	"context"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// CrashReport is a crash report the engine saved: what status shows of it.
type CrashReport struct {
	ID      string
	Time    time.Time
	Version string
	Command string
	// IssueURL is the link that opens a prefilled issue, at most limit
	// characters long; "" when none fits.
	IssueURL func(limit int) string
}

// ReleaseNotice is a newer release the engine knows of.
type ReleaseNotice struct {
	Current  string
	Latest   string
	Security bool
	URL      string
}

// EngineRecord is this engine's row in the agent's database: its identity
// and whether it was revoked.
type EngineRecord struct {
	RecordedAt time.Time
	RevokedAt  *time.Time
}

// CatalogAccess is what the agent's role can read and write, as quoted
// resource names.
type CatalogAccess struct {
	Read       []string
	Write      []string
	NotGranted []string
}

// Service is the status use case: the status tool, the call admission, the
// setup the agent waits for and the warnings that come from the guard's state.
// It holds its own copy of the core settings and a reference to its own Deps,
// and owns the pending setup state. It reads nothing from the other use cases.
type Service struct {
	core Core
	deps *Deps
	// pending is the agent's pending setup and what finishing it keeps.
	pending *handoff.SetupKeeper
}

// New returns the status use case over core and deps. It fills in
// what deps leaves out: no probe reads a current guard, no finisher only
// forgets the setup in memory, and the upgrade check asks the probe.
func New(core Core, deps *Deps) *Service {
	if deps.Probe == nil {
		deps.Probe = noProbe{latest: deps.LatestGuardVersion}
	}
	if deps.Finisher == nil {
		deps.Finisher = handoff.NoFinisher{}
	}
	if deps.Upgrade == nil {
		deps.Upgrade = guardUpgrade{probe: deps.Probe}
	}
	if deps.Build == "" {
		deps.Build = buildinfo.Version
	}
	return &Service{core: core, deps: deps, pending: handoff.NewSetupKeeper(deps.Setup)}
}

// The reads the plugin use case makes of the status group, read as it stands.

// SameUser says the engine runs as the person's own OS user.
func (sc *Service) SameUser() bool { return sc.deps.SameUser }

// DevLocalPages says engine.json has devLocalPages set.
func (sc *Service) DevLocalPages() bool { return sc.deps.DevLocalPages }

// VaultState is the engine's Vault state, VaultOff when there is no Vault reporter.
func (sc *Service) VaultState() string {
	if sc.deps.Vault == nil {
		return VaultOff
	}
	return sc.deps.Vault.VaultStatus().State
}

// The Vault connection's states in status.vault.state.
const (
	VaultOff       = "OFF"
	VaultConnected = "CONNECTED"
	VaultKeyError  = "KEY_ERROR"
)

// GuardStatus reads the guard's state on the agent's credential.
func (sc *Service) GuardStatus(ctx context.Context) (guardmodel.Status, error) {
	return sc.deps.Probe.GuardStatus(ctx)
}
