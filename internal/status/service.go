package status

import (
	"context"
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// Core is what the status use case reads of the agent's shared settings: who
// the agent is, the log and clock, the commands the person runs, how errors map
// to the contract and where the pages are. It is a copy taken when the service
// is built.
type Core struct {
	Name        string
	Log         *slog.Logger
	Now         func() time.Time
	Commands    guidance.Commands
	Errors      guidance.ErrorMap
	PagesBase   string
	PagesOrigin string
	LinkBudget  int
}

// Deps is what the status tool reports beyond the database, all
// optional unless noted (CONTRACT.md, MCP tools, status).
type Deps struct {
	// Passkeys lists the person's passkeys, to count them; required.
	Passkeys PasskeyLister
	// OperatedBy is engine.json operatedBy (PERSON when empty); SameUser is
	// an engine run as the person's own OS user (enforcement GUARD_ONLY);
	// Setup is the agent's pending setup code from the config; Build is the
	// engine's build (buildinfo.Version when empty).
	OperatedBy string
	SameUser   bool
	// DevLocalPages is engine.json devLocalPages: every personMessage starts
	// with the DEV_LOCAL_PAGES warning and status reports the problem
	// (CONTRACT.md, Page origins).
	DevLocalPages bool
	// ConnectBudget is the link budget for the connect link when the
	// engine hands one (config.ConnectLinkBudget), else 0: next steps for a
	// pending setup then put the link first (CONTRACT.md, Connect).
	ConnectBudget int
	Setup         *config.Setup
	Build         string
	// StartedBy is why this engine started: hand, mcp or crash (status
	// engine.startedBy); empty reports nothing.
	StartedBy string
	// Probe reads the guard's state and the agent's setups on its
	// credential, for status and to admit each call; a current guard when
	// nil.
	Probe Probe
	// Upgrade says whether only non-breaking guard migrations are missing
	// (the GUARD_UPGRADE_AVAILABLE warning); optional, Probe answers when nil.
	Upgrade UpgradeChecker
	// Vault reports the engine's Vault connection for status; status leaves
	// vault out when nil.
	Vault VaultReporter
	// Update gives the newer release the engine knows of, from its daily
	// check (CONTRACT.md, Update notice); optional, nil or a nil result
	// when none.
	Update func() *ReleaseNotice
	// Portal reports the engine's last daily portal check for status
	// (problem PORTAL_MISMATCH); status says nothing about the portal when
	// nil.
	Portal PortalReporter
	// Plugins reports the engine's plugin entries listed for this agent
	// that do not serve it (problems PLUGIN_UNAVAILABLE and
	// PLUGIN_NOT_TRUSTED); status says nothing about plugins when nil.
	Plugins PluginReporter
	// CrashDirs are the directories crash reports are saved in, for
	// status.crash; Access lists the resources the agent's role can use, for
	// status.access. Each is left out of status when nil or empty.
	CrashDirs []string
	Access    AccessReader
	// EngineRecord reads this engine's row in the agent's database for the
	// status tool's engineRecord; nil makes its state UNKNOWN.
	EngineRecord EngineRecordReader
	// Trust says what verifies the agent's database certificate now (status
	// trust, problems TRUST_ROOT_EXPIRING and TRUST_PROFILE_REFUSED); status
	// leaves trust out when nil.
	Trust TrustReporter
	// Database names the database the agent's credential connects to, as
	// status names a connect-only setup's database ("<host>:<port>, database
	// <db>"); empty when unknown.
	Database string
	// Finisher finishes a setup the database shows recorded: it promotes a
	// rotated credential and clears setup from engine.json. Optional: the
	// setup is then only forgotten in memory.
	Finisher handoff.SetupFinisher
	// The functions that read the host: all required.
	// CrashReports are the crash reports in dirs, newest first.
	CrashReports func(dirs ...string) []CrashReport
	// CrashFile is the file of report id in the first of dirs that has
	// one, "" when none does.
	CrashFile func(dirs []string, id string) string
	// LatestGuardVersion is the basalt_meta version this build installs.
	LatestGuardVersion func() int
	// UpdateMessage is the notice for the agent to relay, for the binary
	// at exe.
	UpdateMessage func(n ReleaseNotice, exe string) string
	// StartHoldOffUntil is when the supervisor tries the engine again after
	// it gave up (false when it holds nothing off).
	StartHoldOffUntil func(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool)
}

// PasskeyLister lists the person's passkeys.
type PasskeyLister interface {
	Passkeys(ctx context.Context) ([]passkey.Credential, error)
}

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

// NewService returns the status use case over core and deps. It fills in
// what deps leaves out: no probe reads a current guard, no finisher only
// forgets the setup in memory, and the upgrade check asks the probe.
func NewService(core Core, deps *Deps) *Service {
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
