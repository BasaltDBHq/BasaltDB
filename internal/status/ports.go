package status

import (
	"context"
	"net/textproto"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// PluginReporter is what status reads of the engine's plugins: the problems
// of an agent's plugins, added to the status's list with their steps, and
// the health of the plugin entries that serve it. Optional: without one,
// status says nothing about plugins.
type PluginReporter interface {
	AddPluginProblems(ps *guidance.Problems, agent string)
	PluginHealth(agent string) []guidance.PluginHealth
}

// PasskeyLister lists the person's passkeys.
type PasskeyLister interface {
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
}

// Probe reads, on the agent's own credential, what status reports from the
// database and what decides whether a tool call is served. The default
// reports a current guard and no setups.
type Probe interface {
	GuardStatus(ctx context.Context) (guardmodel.Status, error)
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	LatestSetup(ctx context.Context) (guardmodel.AgentSetup, bool, error)
	// LedgerBytes is the size of basalt_meta (status.ledger).
	LedgerBytes(ctx context.Context) (int64, error)
	// Reinstalls are the reinstalls the ledger and the engine's kept copy
	// record (problem LEDGER_REINSTALLED).
	ReinstallNotice(ctx context.Context, limit int) (message string, ok bool, err error)
}

// VaultReporter says how the engine's connection to the hosted Vault stands
// (status.vault, CONTRACT.md, Vault channel, Configuration and status).
// Optional: without one, status leaves vault out.
type VaultReporter interface {
	VaultStatus() guidance.VaultStatus
}

// PortalReporter gives the last daily portal check. Optional: without one,
// or before the first check, status says nothing about the portal.
type PortalReporter interface {
	PortalFinding() (PortalFinding, bool)
}

// Host is what the update check reads from the environment and the build:
// the environment's off switch and the version of a build with no release
// number.
type Host interface {
	// UpdateDisabled reports whether the environment turns the check off.
	UpdateDisabled(getenv func(string) string) bool
	// UpdateDevVersion is the version of a build with no release number.
	UpdateDevVersion() string
}

// Terminal is the engine config a command would read by default, as the
// CLI shell finds and reads it.
type Terminal interface {
	// Euid is the effective user id.
	Euid() int
	// DiscoverConfig is the engine.json a command finds by itself, system
	// being the system path.
	DiscoverConfig(system string) (string, error)
	// LoadEngineConfigAs reads the engine config at path for a process
	// with effective uid euid.
	LoadEngineConfigAs(euid int, path string) (config.Config, error)
}

// UpgradeChecker says whether the guard misses only non-breaking migrations,
// so everything works and the setup page's update adds them. The default asks the
// service's Probe.
type UpgradeChecker interface {
	UpgradeAvailable(ctx context.Context) (bool, error)
}

// PageFetcher fetches one path of the portal the check compares (Verify):
// a GET of urlPath under the portal's origin, with its status code, its
// response header and at most limit bytes of its body. An error says why
// the path could not be fetched, in the words the report shows
// (File.Detail). out/portalfetch implements it over HTTPS.
type PageFetcher interface {
	Get(ctx context.Context, urlPath string, limit int64) (code int, header textproto.MIMEHeader, body []byte, err error)
}
