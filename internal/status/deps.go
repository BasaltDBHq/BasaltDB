package status

import (
	"log/slog"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
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
	// StartedBy is why this engine started: hand, mcp, crash or service (status
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
