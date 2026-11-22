package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/handoff"
	"github.com/basaltdbhq/basaltdb/internal/engine/laststop"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The status tool (CONTRACT.md, MCP tools, status; api/mcp/tools/status.json).
// The engine answers it with what it reads from the agent's database; the
// shim answers it with EngineDownStatus when the engine socket does not.

const toolStatus = "status"

// Problem codes of the status tool (api/mcp/errors/next-steps.json, problems).
const (
	problemEngineUnreachable   = reasonEngineUnreachable
	problemDatabaseUnreachable = reasonDatabaseUnreachable
	problemTooManyConnections  = reasonTooManyConnections
	problemCredentialRejected  = reasonCredentialRejected
	problemGuardMissing        = reasonGuardMissing
	problemGuardOutdated       = reasonGuardOutdated
	problemUpgradeAvailable    = "GUARD_UPGRADE_AVAILABLE"
	problemNoPasskey           = "NO_PASSKEY"
	problemSetupNotRun         = "SETUP_NOT_RUN"
	problemSetupExpired        = "SETUP_EXPIRED"
	problemSetupChangePending  = "SETUP_CHANGE_PENDING"
	problemLockFileUnusable    = "LOCK_FILE_UNUSABLE"
	problemLedgerReinstalled   = "LEDGER_REINSTALLED"
	problemPortalMismatch      = "PORTAL_MISMATCH"
	problemEngineRevoked       = "ENGINE_REVOKED"
	// The problems of a connect-only setup (CONTRACT.md, The engine and a
	// connect-only code).
	problemConfirmDatabase    = "CONFIRM_DATABASE"
	problemDatabaseRefused    = "DATABASE_REFUSED"
	problemUnreachableFromBot = "DATABASE_UNREACHABLE_FROM_BOT"
	problemTrustRootMismatch  = "TRUST_ROOT_MISMATCH"
	problemAddressInvalid     = "ADDRESS_INVALID"
	problemSetupNotFound      = "SETUP_NOT_FOUND"
	problemClockSkew          = "CLOCK_SKEW"
	problemEngineAsRoot       = "ENGINE_AS_ROOT"
	// problemEngineStartFailed: basalt mcp tried to start the engine and
	// could not (CONTRACT.md, MCP tools, status).
	problemEngineStartFailed = "ENGINE_START_FAILED"
	// problemEngineGaveUp: the supervisor gave up restarting a crashing
	// engine (status engine.lastStop).
	problemEngineGaveUp = "ENGINE_GAVE_UP"
)

// status.engineRecord.state (CONTRACT.md, Configuration and status).
const (
	engineRecorded    = "RECORDED"
	engineNotRecorded = "NOT_RECORDED"
	engineRevoked     = "REVOKED"
	engineUnknown     = "UNKNOWN"
)

// engineRecordTimeout bounds the read of the engine's record for status.
const engineRecordTimeout = 5 * time.Second

// EngineRecordReader reads this engine's row in the agent's database
// (guard.EngineRecord): nil when it is not recorded, an error when the
// guard is older than version 33 or the database cannot be read.
type EngineRecordReader func(ctx context.Context, engineID string) (*guard.RecordedEngine, error)

// Retention of the ledger (CONTRACT.md, Configuration and status): the
// guard prunes values after 30 days and deletes records after 365.
const (
	ledgerValuesKeptDays  = 30
	ledgerRecordsKeptDays = 365
)

// Enforcement values of the status tool.
const (
	EnforcementEngineAndGuard = "ENGINE_AND_GUARD"
	EnforcementGuardOnly      = "GUARD_ONLY"
)

// Setup states of the status tool.
const (
	setupNone    = "NONE"
	setupPending = "PENDING"
	setupExpired = "EXPIRED"
	setupDone    = "DONE"
	// setupConfirmDatabase: a connect-only setup's database was collected
	// and probed, and waits for the person's confirmation.
	setupConfirmDatabase = "CONFIRM_DATABASE"
	// setupRefused: the person said the collected database is not theirs.
	setupRefused = "REFUSED"
)

// Probe reads, on the agent's own credential, what status reports from the
// database and what decides whether a tool call is served. The default
// reports a current guard and no setups.
type Probe interface {
	GuardStatus(ctx context.Context) (guard.Status, error)
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	LatestSetup(ctx context.Context) (guard.AgentSetup, bool, error)
	// LedgerBytes is the size of basalt_meta (status.ledger).
	LedgerBytes(ctx context.Context) (int64, error)
	// Reinstalls are the reinstalls the ledger and the engine's kept copy
	// record (problem LEDGER_REINSTALLED).
	Reinstalls(ctx context.Context) (guard.Reinstalls, error)
}

type noProbe struct{}

func (noProbe) GuardStatus(context.Context) (guard.Status, error) {
	v := guard.LatestVersion()
	return guard.Status{State: guard.GuardOK, Installed: v, Build: v}, nil
}

func (noProbe) SetupRecorded(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (noProbe) LatestSetup(context.Context) (guard.AgentSetup, bool, error) {
	return guard.AgentSetup{}, false, nil
}

// errNoProbe: without a real probe there is no size to report, and status
// leaves the ledger out rather than say 0.
var errNoProbe = errors.New("no probe reads the ledger size")

func (noProbe) LedgerBytes(context.Context) (int64, error) { return 0, errNoProbe }

func (noProbe) Reinstalls(context.Context) (guard.Reinstalls, error) { return guard.Reinstalls{}, nil }

// VaultReporter says how the engine's connection to the hosted Vault stands
// (status.vault, CONTRACT.md, Vault channel, Configuration and status).
// Optional: without one, status leaves vault out.
type VaultReporter interface {
	VaultStatus() VaultStatus
}

// VaultStatus is status.vault: state is OFF, CONNECTING, CONNECTED,
// UNREACHABLE or KEY_ERROR; the engine id and its fingerprint whenever the
// key file loads.
type VaultStatus struct {
	State       string `json:"state"`
	EngineID    string `json:"engineId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// PortalFinding is what the engine's daily portal check last found
// (CONTRACT.md, CLI, basalt portal verify). Mismatch is true when the portal
// serves other pages than this build embeds; Summary counts them by status,
// for example "2 DIFFERS, 1 MISSING".
type PortalFinding struct {
	CheckedAt time.Time
	Mismatch  bool
	Summary   string
}

// PortalReporter gives the last daily portal check. Optional: without one,
// or before the first check, status says nothing about the portal.
type PortalReporter interface {
	PortalFinding() (PortalFinding, bool)
}

// EngineRecordStatus is status.engineRecord: this engine's key as the
// agent's database records it (CONTRACT.md, Vault channel, Engine keys).
type EngineRecordStatus struct {
	State      string `json:"state"`
	RecordedAt string `json:"recordedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

// StatusReport is the status tool's result.
type StatusReport struct {
	Agent       string         `json:"agent"`
	OperatedBy  string         `json:"operatedBy"`
	Enforcement string         `json:"enforcement"`
	Ready       bool           `json:"ready"`
	Engine      EngineStatus   `json:"engine"`
	Guard       GuardStatus    `json:"guard"`
	Setup       SetupStatus    `json:"setup"`
	Pages       PagesStatus    `json:"pages"`
	Vault       *VaultStatus   `json:"vault,omitempty"`
	Passkeys    PasskeysStatus `json:"passkeys"`
	Ledger      *LedgerStatus  `json:"ledger,omitempty"`
	// EngineRecord is the engine's own key in the agent's database; absent
	// when the engine is down.
	EngineRecord *EngineRecordStatus `json:"engineRecord,omitempty"`
	// Trust is what verifies the agent's database certificate; absent when
	// the engine is down.
	Trust *TrustStatus `json:"trust,omitempty"`
	// Crash is the newest saved crash report, Access what the agent can
	// read and write, Plugins the health of the plugin entries served to
	// it; each absent when there is nothing to show.
	Crash    *CrashStatus   `json:"crash,omitempty"`
	Access   *AccessStatus  `json:"access,omitempty"`
	Plugins  []PluginHealth `json:"plugins,omitempty"`
	Problems []Problem      `json:"problems"`
	// Update is set when a newer release is out (CONTRACT.md, Update
	// notice).
	Update *UpdateInfo `json:"update,omitempty"`
}

// UpdateInfo is the update field of status and of describe's overview: the
// newer release and what the agent tells the person.
type UpdateInfo struct {
	Current  string `json:"current"`
	Latest   string `json:"latest"`
	Security bool   `json:"security"`
	URL      string `json:"url"`
	// Message starts WARNING: or SECURITY UPDATE: and is meant to be
	// relayed to the person.
	Message string `json:"message"`
}

// updateInfo is the Service's newer release, or nil.
func (s *Service) updateInfo() *UpdateInfo {
	if s.Update == nil {
		return nil
	}
	n := s.Update()
	if n == nil {
		return nil
	}
	info := NewUpdateInfo(*n, executablePath())
	return &info
}

// NewUpdateInfo is the update field for notice n, with the message for
// the binary at exe.
func NewUpdateInfo(n updatecheck.Notice, exe string) UpdateInfo {
	return UpdateInfo{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL, Message: n.AgentMessage(exe)}
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
func (s *Service) UpdateNotice() string {
	if u := s.updateInfo(); u != nil {
		return u.Message
	}
	return ""
}

// executablePath is this binary's path, for the Homebrew hint; "" when
// unknown.
func executablePath() string {
	p, _ := os.Executable()
	return p
}

// EngineStatus is status.engine.
type EngineStatus struct {
	Reachable bool   `json:"reachable"`
	Build     string `json:"build,omitempty"`
	// StartedBy is why this engine started: HAND, MCP or CRASH.
	StartedBy string `json:"startedBy,omitempty"`
	// LastStop is why a supervisor gave up on the engine, from an engine
	// that does not answer; the engine itself never reports it.
	LastStop *LastStop `json:"lastStop,omitempty"`
}

// LastStop is status.engine.lastStop: the supervisor gave up restarting the
// engine for Reason at At.
type LastStop struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
	// EngineSHA256 is last-stop.json's engineSha256, used only to decide
	// the start hold-off; it is never sent in status.
	EngineSHA256 string `json:"-"`
}

// GuardStatus is status.guard.
type GuardStatus struct {
	State              string `json:"state"`
	Installed          *int   `json:"installed,omitempty"`
	Build              int    `json:"build,omitempty"`
	MissingBreaking    []int  `json:"missingBreaking,omitempty"`
	MissingNonBreaking []int  `json:"missingNonBreaking,omitempty"`
}

// SetupStatus is status.setup.
type SetupStatus struct {
	State       string `json:"state"`
	SetupID     string `json:"setupId,omitempty"`
	Kind        string `json:"kind,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// ConnectOnly is set while the pending code is connect-only.
	ConnectOnly bool `json:"connectOnly,omitempty"`
	// Database is the collected and probed database (CONFIRM_DATABASE).
	Database *handoff.Address `json:"database,omitempty"`
}

// PagesStatus is status.pages.
type PagesStatus struct {
	Served bool   `json:"served"`
	URL    string `json:"url"`
}

// PasskeysStatus is status.passkeys; Active is absent when the engine is
// down or cannot count them.
type PasskeysStatus struct {
	Registered bool `json:"registered"`
	Active     *int `json:"active,omitempty"`
	// Keys names each active passkey with its check code, computed from the
	// public key in the database (CONTRACT.md, Connect, The passkey check
	// code); absent when none is active or they cannot be read.
	Keys []PasskeyStatus `json:"keys,omitempty"`
	// Summary is the same in words for the person, set once a setup is
	// recorded (state DONE).
	Summary string `json:"summary,omitempty"`
}

// PasskeyStatus is one entry of status.passkeys.keys. CheckCode is absent
// when the key cannot be read.
type PasskeyStatus struct {
	CredentialID passkey.Bytes `json:"credentialId"`
	CheckCode    string        `json:"checkCode,omitempty"`
}

// LedgerStatus is status.ledger: absent when the guard or its size cannot
// be read.
type LedgerStatus struct {
	Bytes           int64 `json:"bytes"`
	ValuesKeptDays  int   `json:"valuesKeptDays"`
	RecordsKeptDays int   `json:"recordsKeptDays"`
}

// Problem is one entry of status.problems.
type Problem struct {
	Code          string `json:"code"`
	Severity      string `json:"severity"`
	Message       string `json:"message"`
	PersonMessage string `json:"personMessage,omitempty"`
	// Links are the URLs of PersonMessage, with labels (present exactly when
	// it holds a URL).
	Links     []mcp.Link `json:"links,omitempty"`
	NextSteps []NextStep `json:"nextSteps"`
}

// Status is the status tool: whether the agent is served and each problem
// with its steps. It never fails on what it reads: an unreachable database
// or a missing guard is a problem in the result, not an error. It never
// names the credential file.
func (s *Service) Status(ctx context.Context) (StatusReport, error) {
	return s.statusDeps().report(ctx)
}

// statusDeps are what a status report reads: the Service's own in the
// engine, LocalStatus's for basalt status on an engine run as the person.
type statusDeps struct {
	name, operatedBy, build   string
	startedBy                 string
	pagesBase, pagesOrigin    string
	sameUser, engineReachable bool
	engineUnknown             bool
	devLocalPages             bool
	connectBudget             int
	vault                     VaultReporter
	portal                    PortalReporter
	plugins                   PluginReporter
	crashDirs                 []string
	linkBudget                int
	access                    AccessReader
	update                    *UpdateInfo
	// engineKey is the engine id basalt status read from the running
	// engine's key file ("" when it is refused), nil when it reports no
	// engine record (LocalStatus.EngineKey); the engine uses vault.
	engineKey    *string
	engineRecord EngineRecordReader
	trust        TrustReporter
	// database names the credential's database (Deps.Database).
	database string
	cmds     Commands
	setup    *config.Setup
	probe    Probe
	finisher SetupFinisher
	// finished forgets the pending setup once the database shows it
	// recorded.
	finished func(id string)
	// notRecorded remembers, for a few seconds, that a held call found the
	// pending setup not recorded (setupGate).
	notRecorded *setupCache
	// lockTrouble is the lock file finishing a setup could not open.
	lockTrouble *lockTrouble
	passkeys    func(context.Context) ([]passkey.Credential, error)
	log         *slog.Logger
	now         func() time.Time
}

func (s *Service) statusDeps() statusDeps {
	return statusDeps{
		name: s.Name, operatedBy: s.OperatedBy, build: s.Build, startedBy: s.StartedBy, pagesBase: s.PagesBase, pagesOrigin: s.PagesOrigin,
		sameUser: s.SameUser, devLocalPages: s.DevLocalPages, connectBudget: s.ConnectBudget, engineReachable: true, vault: s.Vault, portal: s.Portal, plugins: s.Plugins,
		crashDirs: s.CrashDirs, linkBudget: s.LinkBudget, access: s.Access,
		engineRecord: s.EngineRecord, trust: s.Trust, database: s.Database, cmds: s.Commands, setup: s.pendingSetup(), probe: s.Probe,
		update: s.updateInfo(), finisher: s.Finisher, finished: s.setupFinished, notRecorded: &s.notRecorded, lockTrouble: &s.lockTrouble, passkeys: s.Store.Passkeys, log: s.Log, now: s.Now,
	}
}

// LocalStatus is what basalt status reads for an agent whose engine runs as
// the person's own OS user (same-user mode): the config, the agent's own
// credential and whether the engine process runs. Its report is the status
// tool's, with engine.reachable from the process and ENGINE_UNREACHABLE
// when it does not run.
type LocalStatus struct {
	Name       string
	Commands   Commands
	OperatedBy string
	Setup      *config.Setup
	// PagesBase is the config's pages base URL; PagesOrigin is the origin
	// of the local pages when the running engine serves them, else empty.
	PagesBase, PagesOrigin string
	EngineRunning          bool
	// EngineUnknown: whether the engine runs cannot be told, so there is
	// no ENGINE_UNREACHABLE problem (engine.reachable stays false).
	EngineUnknown bool
	// DevLocalPages is the config's devLocalPages (problem DEV_LOCAL_PAGES).
	DevLocalPages bool
	// Collected is, for a connect-only setup, what basalt status collected
	// while the engine is down (same-user mode); nil reports the setup
	// from engine.json alone.
	Collected *handoff.State
	// ConnectBudget is the config's config.ConnectLinkBudget (0: no connect
	// link).
	ConnectBudget int
	// Portal is the last daily portal check the engine saved (problem
	// PORTAL_MISMATCH); nil when the config names no portal.
	Portal PortalReporter
	// EngineKey, for an engine that runs and whose key file this user
	// reads, is its engine id ("" when the key file is refused): the report
	// then has engineRecord, read with EngineRecord, and its problems. Nil
	// leaves engineRecord out, as for an engine that is down.
	EngineKey    *string
	EngineRecord EngineRecordReader
	// Trust: see Deps.Trust.
	Trust    TrustReporter
	Probe    Probe
	Passkeys func(context.Context) ([]passkey.Credential, error)
	Log      *slog.Logger
	Now      func() time.Time
}

// Report is the status report. It panics on a missing probe, passkey
// reader, logger or clock.
func (l LocalStatus) Report(ctx context.Context) (StatusReport, error) {
	if l.Probe == nil || l.Passkeys == nil || l.Log == nil || l.Now == nil {
		panic("agent: local status needs a probe, a passkey reader, a logger and a clock")
	}
	base := l.PagesBase
	if base == "" {
		base = links.DefaultLocal
	}
	return statusDeps{
		name: l.Name, operatedBy: l.OperatedBy, build: buildinfo.Version, pagesBase: base, pagesOrigin: l.PagesOrigin,
		sameUser: true, devLocalPages: l.DevLocalPages, connectBudget: l.ConnectBudget, portal: l.Portal, engineReachable: l.EngineRunning, engineUnknown: l.EngineUnknown, cmds: l.Commands, setup: l.Setup, probe: l.Probe,
		engineKey: l.EngineKey, engineRecord: l.EngineRecord, trust: l.Trust,
		// basalt status reads; the running engine finishes the setup.
		finisher: noFinisher{}, finished: func(string) {}, notRecorded: &setupCache{}, lockTrouble: &lockTrouble{}, passkeys: l.Passkeys, log: l.Log, now: l.Now,
	}.report(ctx)
}

func (s statusDeps) report(ctx context.Context) (StatusReport, error) {
	s.cmds = s.cmds.OperatedBy(s.operatedBy)
	r := StatusReport{
		Agent: s.name, OperatedBy: operatedBy(s.operatedBy), Enforcement: enforcement(s.operatedBy, s.sameUser),
		Engine: EngineStatus{Reachable: s.engineReachable, Build: s.build, StartedBy: startedByEnum(s.startedBy)},
		Pages:  PagesStatus{Served: s.pagesOrigin != "", URL: s.pagesBase},
		Update: s.update,
	}
	if s.vault != nil {
		v := s.vault.VaultStatus()
		r.Vault = &v
	}
	ps := problems{cmds: s.cmds, connectBudget: s.connectBudget}
	if s.devLocalPages {
		ps.add(problemDevLocalPages, "the pages are development pages on this machine, not the portal",
			func(b *Steps) string { return devLocalPagesSteps(b, s.cmds) })
	}
	if !s.engineReachable && !s.engineUnknown {
		ps.add(problemEngineUnreachable, "the engine is not running, so the agent's tools do not answer",
			func(b *Steps) string { return engineUnreachableSteps(b, s.cmds, toolStatus) })
	}
	s.addPortalProblem(&ps)
	s.addPluginProblems(&ps)
	var trust *TrustReport
	r.Trust, trust = s.trustStatus(ctx, &ps)
	setup, known := s.setupView(ctx)
	r.Setup = setup.status
	if path := s.lockTrouble.get(); path != "" {
		ps.add(problemLockFileUnusable, "the engine cannot open "+path+", so a finished setup is not written back",
			func(b *Steps) string { return lockFileSteps(b, path) })
	}
	if known {
		// A setup whose recorded state could not be read (the database is
		// down) gets no problem: the code may have been used already.
		setup.addProblem(&ps)
	}

	st, err := s.probe.GuardStatus(ctx)
	// A pending INSTALL code explains a role that cannot log in or a guard
	// that is not there yet; any other failure is reported as it is.
	explained := known && setup.explainsGuard() && notInstalledYet(st, err)
	switch {
	case err != nil:
		r.Guard = GuardStatus{State: guard.GuardUnknown, Build: guard.LatestVersion()}
		if !explained {
			s.addUnreachable(ctx, &ps, err, trust)
		}
	default:
		r.Guard = guardStatusDTO(st)
		if !explained {
			addGuardProblem(&ps, st)
		}
	}
	if err == nil && st.State != guard.GuardMissing {
		r.Passkeys = s.countPasskeys(ctx, &ps, setup.status.State == setupDone)
	}
	if err == nil {
		r.Ledger = s.ledgerStatus(ctx, st)
	}
	r.Crash, r.Plugins = s.crashStatus(), s.pluginHealth()
	if err == nil && st.State != guard.GuardMissing {
		r.Access = s.accessStatus(ctx)
	}
	readable := err == nil && st.State != guard.GuardMissing
	if readable {
		s.addReinstalled(ctx, &ps)
	}
	switch {
	case s.vault != nil && r.Vault != nil:
		r.EngineRecord = s.engineRecordStatus(ctx, r.Vault.EngineID, readable, &ps)
	case s.engineKey != nil:
		r.EngineRecord = s.engineRecordStatus(ctx, *s.engineKey, readable, &ps)
	}
	list, err := ps.sorted()
	if err != nil {
		return StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

// EngineDownStatus is status as the shim answers it when the engine socket
// does not answer: engine unreachable, guard UNKNOWN, operatedBy from the
// config the shim could read (cfg nil: it could not, so PERSON and
// GUARD_ONLY), the pending setup when the config holds one.
func EngineDownStatus(name string, cmds Commands, cfg *config.Config, cfgErr error, build string, now time.Time) (StatusReport, error) {
	return EngineDownStatusAfterStart(name, cmds, cfg, cfgErr, build, now, "", "")
}

// EngineDownStatusAfterStart is EngineDownStatus for a basalt mcp that tried
// to start the engine: startFailure, when not empty, is why it could not
// ("basalt mcp could not start the engine: <reason>. Its log is <path>."),
// shown as the problem ENGINE_START_FAILED before ENGINE_UNREACHABLE, whose
// steps stay.
func EngineDownStatusAfterStart(name string, cmds Commands, cfg *config.Config, cfgErr error, build string, now time.Time, startFailure, configPath string) (StatusReport, error) {
	r := StatusReport{
		Agent: name, OperatedBy: mcpcontract.OperatedByPerson, Enforcement: EnforcementGuardOnly,
		Engine: EngineStatus{Reachable: false, Build: build},
		Guard:  GuardStatus{State: guard.GuardUnknown, Build: guard.LatestVersion()},
		Setup:  SetupStatus{State: setupNone},
		Pages:  PagesStatus{URL: links.DefaultLocal},
	}
	if cfg != nil {
		cmds = cmds.OperatedBy(cfg.OperatedBy)
	}
	ps := problems{cmds: cmds}
	msg := "the engine does not answer, so no tool but status works"
	if config.IsOldCredentialFile(cfgErr) {
		// The engine cannot start on this config: say what to edit.
		msg += "; engine.json: " + cfgErr.Error()
	}
	if startFailure != "" {
		ps.add(problemEngineStartFailed, startFailure,
			func(b *Steps) string { return engineUnreachableSteps(b, cmds, toolStatus) })
	}
	ps.add(problemEngineUnreachable, msg,
		func(b *Steps) string { return engineUnreachableSteps(b, cmds, toolStatus) })
	if cfg != nil {
		if stop, ok := ReadLastStop(cfg.StateDirFor(runtime.GOOS)); ok {
			r.Engine.LastStop = &stop
			ps.add(problemEngineGaveUp, engineGaveUpMessage(stop, configPath, now),
				func(b *Steps) string { return engineUnreachableSteps(b, cmds, toolStatus) })
		}
		r.OperatedBy = operatedBy(cfg.OperatedBy)
		r.Enforcement = enforcement(cfg.OperatedBy, !cfg.Service())
		if base, err := cfg.PagesBase(); err == nil {
			r.Pages.URL = base
		}
		if a, ok := configAgent(cfg, name); ok {
			setup := setupFrom(a.Setup, false, now)
			r.Setup = setup.status
			setup.addProblem(&ps)
		}
	}
	list, err := ps.sorted()
	if err != nil {
		return StatusReport{}, err
	}
	r.Problems, r.Ready = list, ready(list)
	return r, nil
}

func configAgent(cfg *config.Config, name string) (config.Agent, bool) {
	for _, a := range cfg.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return config.Agent{}, false
}

func operatedBy(v string) string {
	if v == mcpcontract.OperatedByAgent {
		return v
	}
	return mcpcontract.OperatedByPerson
}

// enforcement is GUARD_ONLY when the agent could use its credential
// directly: it operates the machine, or the engine runs as the person.
func enforcement(operated string, sameUser bool) string {
	if operated == mcpcontract.OperatedByAgent || sameUser {
		return EnforcementGuardOnly
	}
	return EnforcementEngineAndGuard
}

func ready(list []Problem) bool {
	for _, p := range list {
		if p.Severity == mcpcontract.SeverityError {
			return false
		}
	}
	return true
}

func guardStatusDTO(st guard.Status) GuardStatus {
	out := GuardStatus{State: st.State, Build: st.Build, MissingBreaking: st.MissingBreaking, MissingNonBreaking: st.MissingNonBreaking}
	if st.State != guard.GuardMissing {
		installed := st.Installed
		out.Installed = &installed
	}
	return out
}

// ledgerStatus is the ledger's size and retention. A missing guard has no
// ledger, and a size that cannot be read is logged and left out: it is
// never a problem.
func (s statusDeps) ledgerStatus(ctx context.Context, st guard.Status) *LedgerStatus {
	if st.State == guard.GuardMissing {
		return nil
	}
	n, err := s.probe.LedgerBytes(ctx)
	if err != nil {
		s.log.Debug("status: read the ledger size", "err", err)
		return nil
	}
	return &LedgerStatus{Bytes: n, ValuesKeptDays: ledgerValuesKeptDays, RecordsKeptDays: ledgerRecordsKeptDays}
}

// reinstalledAsk is LEDGER_REINSTALLED's ASK_PERSON step.
const reinstalledAsk = "Show the person this notice and ask whether someone on their team reinstalled Basalt. " +
	"The tools keep working, and the notice stays until an admin acknowledges it."

// addReinstalled is LEDGER_REINSTALLED when the ledger or the engine's kept
// copy records a reinstall. A guard older than version 36 records none; a
// read that fails is logged and adds nothing.
func (s statusDeps) addReinstalled(ctx context.Context, ps *problems) {
	rs, err := s.probe.Reinstalls(ctx)
	if err != nil {
		s.log.Error("status: read the reinstalls", "err", err)
		return
	}
	msg, ok := ledger.ReinstallPersonMessage(rs, MaxPersonMessageLength)
	if !ok {
		return
	}
	ps.add(problemLedgerReinstalled, "the guard was installed again and a pin of the old ledger was set aside; the tools keep working",
		func(b *Steps) string {
			b.AskPerson(reinstalledAsk)
			return msg
		})
}

// passkeys counts the active passkeys; none is NO_PASSKEY. A count that
// fails is logged and leaves active out.
func (s statusDeps) countPasskeys(ctx context.Context, ps *problems, setupDone bool) PasskeysStatus {
	keys, err := s.passkeys(ctx)
	if err != nil {
		s.log.Error("status: count passkeys", "err", err)
		return PasskeysStatus{}
	}
	n := len(keys)
	if n == 0 {
		ps.add(problemNoPasskey, "no passkey is registered, so held writes and reverts cannot be signed",
			func(b *Steps) string { return noPasskeySteps(b, s.cmds) })
	}
	out := PasskeysStatus{Registered: n > 0, Active: &n}
	for _, k := range keys {
		entry := PasskeyStatus{CredentialID: k.ID}
		code, err := k.CheckCode()
		if err != nil {
			s.log.Error("status: passkey check code", "err", err)
		}
		entry.CheckCode = code
		out.Keys = append(out.Keys, entry)
	}
	if setupDone {
		out.Summary = passkeySummary(out.Keys)
	}
	return out
}

// passkeySummary says in words how many passkeys are registered and the
// check code of each, so the person can compare them with the codes the
// connect page showed (CONTRACT.md, Connect, The passkey check code).
func passkeySummary(keys []PasskeyStatus) string {
	if len(keys) == 0 {
		return ""
	}
	codes := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.CheckCode != "" {
			codes = append(codes, k.CheckCode)
		}
	}
	noun := "passkeys are"
	if len(keys) == 1 {
		noun = "passkey is"
	}
	msg := fmt.Sprintf("%d %s registered", len(keys), noun)
	if len(codes) > 0 {
		msg += ", with check code " + strings.Join(codes, ", check code ")
	}
	if len(codes) < len(keys) {
		msg += fmt.Sprintf(" (the code of %d could not be read)", len(keys)-len(codes))
	}
	return msg + ". If the setup page showed you a check code for the passkey it created, it should be one of these. A passkey you did not create means stop and remove it."
}

// noPasskeySteps: the agent runs basalt init, whose link opens the page
// where the person registers a passkey; on an agent-operated engine the
// connect page (RI-6: the person's computer registers a portal passkey when
// none is active).
func noPasskeySteps(b *Steps, cmds Commands) string {
	const lead = "No passkey is registered for this agent, so nothing it holds for you can be approved yet."
	if cmds.AgentOperated() {
		return remoteSetupSteps(b, cmds, lead)
	}
	b.AgentRunCommand(cmds.Init(), "Run this once and show the person the link it prints, where they register a passkey: held writes and reverts are signed with one.")
	return lead + " The agent gives you a link to register one."
}

// addUnreachable is the problem of a guard read that failed: the database
// refused the credential, or cannot be reached.
func (s statusDeps) addUnreachable(ctx context.Context, ps *problems, err error, trust *TrustReport) {
	if trustprofile.CertificateNotVerified(err) {
		s.addCertificateNotVerified(ctx, ps, err, trust)
		return
	}
	te := ToolError(err)
	switch te.Reason {
	case reasonCredentialRejected:
		ps.add(problemCredentialRejected, "the database refuses the agent's credential",
			func(b *Steps) string { return fixSteps(b, s.cmds, reasonCredentialRejected) })
	case reasonTooManyConnections:
		ps.add(problemTooManyConnections, "the agent's role has used all the database connections it is allowed",
			func(b *Steps) string {
				b.AskPerson(tooManyConnectionsAsk)
				return tooManyConnectionsMessage(s.cmds)
			})
	case reasonGuardMissing:
		ps.add(problemGuardMissing, "the guard is not installed in this database",
			func(b *Steps) string { return fixSteps(b, s.cmds, reasonGuardMissing) })
	default:
		s.log.Error("status: read the guard", "err", err)
		ps.add(problemDatabaseUnreachable, "the database cannot be reached",
			func(b *Steps) string {
				b.AskPerson("Tell the person the database cannot be reached and ask them to check that Postgres is running.")
				return databaseUnreachableMessage
			})
	}
}

func addGuardProblem(ps *problems, st guard.Status) {
	switch st.State {
	case guard.GuardMissing:
		ps.add(problemGuardMissing, "the guard is not installed in this database; no tool but status works",
			func(b *Steps) string { return fixSteps(b, ps.cmds, reasonGuardMissing) })
	case guard.GuardOutdated:
		ps.add(problemGuardOutdated, fmt.Sprintf("the guard misses breaking migrations %s; no tool but status works until it is upgraded", versions(st.MissingBreaking)),
			func(b *Steps) string { return fixSteps(b, ps.cmds, reasonGuardOutdated) })
	case guard.GuardUpgradeAvailable:
		ps.add(problemUpgradeAvailable, fmt.Sprintf("the guard misses non-breaking migrations %s; every tool works", versions(st.MissingNonBreaking)),
			func(b *Steps) string { return upgradeSteps(b, ps.cmds) })
	}
}

func versions(vs []int) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}

// setupView is the agent's setup from the laptop as status reports it.
type setupView struct {
	status SetupStatus
	// code and fingerprint are the pending code's while it is still live
	// (status shows the fingerprint only while pending). An expired code
	// is never reprinted, including during the collect-window hold.
	code, fingerprint string
	// awaiting: a connect-only code whose engine waits for the database's
	// address; refused: the person refused the one it collected; confirmed:
	// a connect-only code whose database the person confirmed, so the
	// engine logs in with its credential.
	awaiting, refused, confirmed bool
	// database names the database of a confirmed connect-only setup.
	database string
}

// explainsGuard reports whether an INSTALL setup is pending or expired: the
// guard and the agent's role are not there yet, so the setup problem is
// the one to fix and the guard and database problems it causes are left out.
func (v setupView) explainsGuard() bool {
	return !v.confirmed && v.status.Kind == guard.SetupInstall && (v.status.State == setupPending || v.status.State == setupExpired)
}

// blocks reports whether the pending setup holds every tool but status: an
// INSTALL code that has not run, or a connect-only code whose database the
// person confirmed and that the database does not record yet.
func (v setupView) blocks() bool {
	return v.explainsGuard() || (v.confirmed && v.status.State == setupPending)
}

func (v setupView) addProblem(ps *problems) {
	switch {
	case v.refused:
		ps.add(problemDatabaseRefused, "the person said the database the setup reached is not theirs; a new setup code is needed",
			func(b *Steps) string { return databaseRefusedSteps(b, ps.cmds) })
	case v.status.State == setupExpired:
		ps.add(problemSetupExpired, "the agent's setup code expired before it was used; a new one is needed",
			func(b *Steps) string { return setupExpiredSteps(b, ps.cmds) })
	case v.status.State != setupPending:
	case v.awaiting:
		ps.addLinked(problemSetupNotRun, connectOnlyWaitingMessage(v.code),
			func(b *Steps) (string, []mcp.Link) {
				return connectOnlySteps(b, v.code, v.fingerprint, ps.connectBudget)
			})
	case v.confirmed:
		ps.add(problemSetupNotFound, "the database the person confirmed does not record this setup: "+v.database,
			func(b *Steps) string { return setupNotFoundSteps(b, ps.cmds, v.database) })
	case v.status.Kind == guard.SetupInstall:
		ps.addLinked(problemSetupNotRun, "the agent's setup has not run yet; no tool but status works until it has",
			func(b *Steps) (string, []mcp.Link) {
				return setupPendingSteps(b, ps.cmds, v.code, v.fingerprint, true, ps.connectBudget)
			})
	default:
		ps.addLinked(problemSetupChangePending, "a setup change is waiting for the person; the tools keep working as installed",
			func(b *Steps) (string, []mcp.Link) {
				return setupPendingSteps(b, ps.cmds, v.code, v.fingerprint, false, ps.connectBudget)
			})
	}
}

// setupView reads the agent's setup: its pending code from the config unless
// it is recorded, else its latest recorded setup. known is false when the
// database cannot tell whether the pending code was used (see
// pendingRecorded); the config's code is then shown, with no problem.
func (s statusDeps) setupView(ctx context.Context) (setupView, bool) {
	recorded, known := false, true
	if s.setup != nil {
		recorded, known = s.pendingRecorded(ctx)
	}
	v := setupFrom(s.setup, recorded, s.now())
	v.database = s.database
	if v.status.State != setupNone || !known {
		return v, known
	}
	latest, ok, err := s.probe.LatestSetup(ctx)
	if err != nil {
		s.log.Error("status: read the latest setup", "err", err)
	}
	if ok {
		v.status = SetupStatus{State: setupDone, SetupID: latest.SetupID.String(), Kind: latest.Kind}
	}
	return v, true
}

// setupFrom is the pending setup's state: PENDING until it expires, then
// EXPIRED for an INSTALL code; an expired AGENT or UPGRADE code is dropped
// (NONE here), as is a recorded one. A connect-only code still waiting for
// its address stays PENDING through the collect window (the code's life
// plus the 30-minute hold), so the engine can pick up a setup that
// finished after expiresAt; the expired code is not reprinted.
func setupFrom(p *config.Setup, recorded bool, now time.Time) setupView {
	if p == nil || recorded {
		return setupView{status: SetupStatus{State: setupNone}}
	}
	connectOnly := connectOnlyCode(p.Code)
	if p.Refused {
		return setupView{refused: true, status: SetupStatus{State: setupRefused, SetupID: p.SetupID, Kind: p.Kind, ConnectOnly: true}}
	}
	expires, err := p.Expires()
	expired := err != nil || !now.Before(expires)
	// A connect-only code the person confirmed stays pending until the
	// database shows it recorded, whatever its expiry: the setup ran.
	confirmed := connectOnly && !p.AwaitingAddress
	if expired && confirmed {
		expired = false
	}
	// Still collecting during the hold after the code expires.
	hold := connectOnly && p.AwaitingAddress && err == nil && now.Before(expires.Add(setupcode.CollectWindow-setupcode.Lifetime))
	if expired && hold {
		expired = false
	}
	if expired && p.Kind != guard.SetupInstall && !p.AwaitingAddress {
		return setupView{status: SetupStatus{State: setupNone}}
	}
	v := setupView{
		code: p.Code, fingerprint: p.Fingerprint, awaiting: p.AwaitingAddress, confirmed: confirmed,
		status: SetupStatus{State: setupPending, SetupID: p.SetupID, Kind: p.Kind, ExpiresAt: p.ExpiresAt, Fingerprint: p.Fingerprint, ConnectOnly: connectOnly},
	}
	if expired {
		v.status.State, v.status.Fingerprint = setupExpired, ""
	}
	if err == nil && !now.Before(expires) {
		// An expired code is never reprinted, even while we still collect.
		v.code, v.fingerprint, v.status.Fingerprint = "", "", ""
	}
	return v
}

// connectOnlyCode reports whether code is a connect-only setup code (it
// has no target). A code that cannot be read is not.
func connectOnlyCode(code string) bool {
	p, err := setupcode.Decode(code)
	return err == nil && p.ConnectOnly()
}

// problems collects status problems, each built from its catalog entry.
type problems struct {
	cmds Commands
	// connectBudget: see Deps.ConnectBudget.
	connectBudget int
	list          []Problem
	err           error
}

// add builds the problem code with the steps steps returns along with the
// person's message.
func (ps *problems) add(code, message string, steps func(*Steps) string) {
	ps.addLinked(code, message, func(b *Steps) (string, []mcp.Link) { return steps(b), nil })
}

// addLinked is add for a message that carries links.
func (ps *problems) addLinked(code, message string, steps func(*Steps) (string, []mcp.Link)) {
	entry, ok := problemEntry(code)
	if !ok {
		ps.fail(fmt.Errorf("no catalog entry for status problem %s", code))
		return
	}
	b := NewSteps()
	person, ls := steps(b)
	list, err := b.Build()
	if err != nil {
		ps.fail(fmt.Errorf("status problem %s: %w", code, err))
		return
	}
	person = fitToSteps(person, list)
	if err := CheckPersonMessage(person); err != nil {
		ps.fail(fmt.Errorf("status problem %s: %w", code, err))
		return
	}
	ps.list = append(ps.list, Problem{Code: code, Severity: entry.Severity, Message: message, PersonMessage: person, Links: ls, NextSteps: list})
}

func (ps *problems) fail(err error) {
	if ps.err == nil {
		ps.err = err
	}
}

// sorted is the problems, errors first, or the first that could not be built.
func (ps *problems) sorted() ([]Problem, error) {
	if ps.err != nil {
		return nil, ps.err
	}
	out := append([]Problem{}, ps.list...)
	slices.SortStableFunc(out, func(a, b Problem) int {
		return cmp.Compare(severityRank(a.Severity), severityRank(b.Severity))
	})
	return out, nil
}

func severityRank(s string) int {
	if s == mcpcontract.SeverityError {
		return 0
	}
	return 1
}

func problemEntry(code string) (mcpcontract.ProblemSteps, bool) {
	for _, p := range catalog().Problems {
		if p.Code == code {
			return p, true
		}
	}
	return mcpcontract.ProblemSteps{}, false
}

// --- the tool ---

func (h handlers) status(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	return h.svc.Status(ctx)
}

// --- admission ---

// Admit refuses a tool call the agent cannot be served yet (CONTRACT.md,
// Next steps, Startup failures): its INSTALL setup code has not run, or
// the guard is not installed or misses a breaking migration. It reads the
// guard on every call, so a guard update needs no engine restart. status is
// never refused.
func (s *Service) Admit(ctx context.Context) error {
	if v, known := s.statusDeps().setupGate(ctx); known && v.blocks() {
		return &SetupError{Code: v.code, Fingerprint: v.fingerprint, Expired: v.status.State == setupExpired, ConnectOnly: v.status.ConnectOnly}
	}
	st, err := s.Probe.GuardStatus(ctx)
	if err != nil {
		return err
	}
	switch st.State {
	case guard.GuardOutdated:
		return &mcp.ToolError{Code: CodeUnavailable, Reason: reasonGuardOutdated, Message: fmt.Sprintf(
			"the guard in this database misses breaking migrations %s of this engine; only status works until the person upgrades it",
			versions(st.MissingBreaking))}
	case guard.GuardMissing:
		return &mcp.ToolError{
			Code: CodeUnavailable, Reason: reasonGuardMissing,
			Message: "the guard is not installed in this database; only status works until the person installs it",
		}
	}
	return nil
}

// setupGate is the pending setup a call checks: none without a pending
// INSTALL code, so an agent without one reads nothing more. known is false
// when the database cannot tell whether the code was used.
func (s statusDeps) setupGate(ctx context.Context) (setupView, bool) {
	if s.setup == nil || (s.setup.Kind != guard.SetupInstall && !connectOnlyCode(s.setup.Code)) {
		return setupView{status: SetupStatus{State: setupNone}}, true
	}
	now := s.now()
	if s.notRecorded.fresh(s.setup.SetupID, now) {
		return setupFrom(s.setup, false, now), true
	}
	recorded, known := s.pendingRecorded(ctx)
	if known && !recorded {
		s.notRecorded.remember(s.setup.SetupID, now)
	}
	return setupFrom(s.setup, recorded, now), known
}

// pendingRecorded reads whether the pending setup code was used. A database
// that refuses the agent's role or has no guard yet means it was not (an
// INSTALL code makes both); any other failure, such as a database that
// cannot be reached, leaves it unknown (known false), logged.
func (s statusDeps) pendingRecorded(ctx context.Context) (recorded, known bool) {
	id, err := uuid.Parse(s.setup.SetupID)
	if err == nil {
		recorded, err = s.recordedAsAgent(ctx, id)
	}
	switch {
	case err == nil:
		return recorded, true
	case notInstalledYet(guard.Status{}, err):
		return false, true
	}
	s.log.Error("read the pending setup", "err", err)
	return false, false
}

// notInstalledYet reports whether a guard read (st, or the error it failed
// with) shows what a pending INSTALL code explains: the agent's role cannot
// log in yet, or the guard is not there yet.
func notInstalledYet(st guard.Status, err error) bool {
	if err == nil {
		return st.State == guard.GuardMissing
	}
	reason := ToolError(err).Reason
	return reason == reasonCredentialRejected || reason == reasonGuardMissing
}

// guardUpgrade answers UpgradeChecker from the probe.
type guardUpgrade struct{ probe Probe }

func (g guardUpgrade) UpgradeAvailable(ctx context.Context) (bool, error) {
	st, err := g.probe.GuardStatus(ctx)
	if err != nil {
		return false, err
	}
	return st.State == guard.GuardUpgradeAvailable, nil
}

// engineRecordStatus reads this engine's record for status and adds its
// problem ENGINE_REVOKED. Without the engine's
// key (the key file is refused) or a readable guard of version 33 or later,
// the state is UNKNOWN and no problem is added.
func (s statusDeps) engineRecordStatus(ctx context.Context, engineID string, guardReadable bool, ps *problems) *EngineRecordStatus {
	unknown := &EngineRecordStatus{State: engineUnknown}
	if engineID == "" || !guardReadable || s.engineRecord == nil {
		return unknown
	}
	rctx, cancel := context.WithTimeout(ctx, engineRecordTimeout)
	defer cancel()
	e, err := s.engineRecord(rctx, engineID)
	if err != nil {
		s.log.Debug("status: read the engine's record", "err", err)
		return unknown
	}
	if e == nil {
		return &EngineRecordStatus{State: engineNotRecorded}
	}
	out := &EngineRecordStatus{State: engineRecorded, RecordedAt: e.RecordedAt.UTC().Format(time.RFC3339)}
	if e.RevokedAt != nil {
		out.State, out.RevokedAt = engineRevoked, e.RevokedAt.UTC().Format(time.RFC3339)
		ps.add(problemEngineRevoked, "the agent's database revoked this engine's key; the engine hands over no relay short link for it and has ended the ones it handed over",
			engineRevokedSteps)
	}
	return out
}

// engineRevokedSteps: the agent asks whether the person revoked this engine
// on purpose. Until a new key is recorded the agent hands over long links.
func engineRevokedSteps(b *Steps) string {
	b.AskPerson("Tell the person this engine's key is revoked in their database. Ask whether they revoked it on purpose, and show the message.")
	b.EndTurn("End your turn: the person answers next.")
	return "This engine's key is revoked in your database. Status shows it; this engine no longer hands over portal short links for it, and the ones it handed over stop working. " +
		"Did you revoke it on purpose? If you replaced the engine, the agent sets it up again and gives you a new link."
}

// startedByEnum is the status enum of a --started-by value ("" for none).
func startedByEnum(v string) string {
	switch v {
	case "hand", "mcp", "crash":
		return strings.ToUpper(v)
	}
	return ""
}

// lastStopFile is what the engine's supervisor writes in the state
// directory when it gives up (cmd/basalt, basalt engine --supervise).
const lastStopFile = "last-stop.json"

// maxLastStopBytes bounds what is read of it; maxReasonRunes what is shown.
const (
	maxLastStopBytes = 4096
	maxReasonRunes   = 300
)

// ReadLastStop reads why the supervisor gave up, from dir (the state
// directory): ok is false when there is no usable record. It is read as
// text and shown, never trusted for anything else.
func ReadLastStop(dir string) (LastStop, bool) {
	// Not a symlink, and never blocking on a pipe someone left there.
	f, err := os.OpenFile(filepath.Join(dir, lastStopFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return LastStop{}, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return LastStop{}, false
	}
	var rec laststop.LastStopFileRecord
	if err := json.NewDecoder(io.LimitReader(f, maxLastStopBytes)).Decode(&rec); err != nil || rec.Reason == "" {
		return LastStop{}, false
	}
	if r := []rune(rec.Reason); len(r) > maxReasonRunes {
		rec.Reason = string(r[:maxReasonRunes])
	}
	rec.Reason = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, rec.Reason)
	return LastStop{Reason: rec.Reason, At: rec.At.UTC(), EngineSHA256: rec.EngineSHA256}, true
}

// engineGaveUpMessage is the ENGINE_GAVE_UP status message: the supervisor's
// reason, and when the next try happens during the hold-off.
func engineGaveUpMessage(stop LastStop, configPath string, now time.Time) string {
	msg := "the engine stopped and was not restarted: " + stop.Reason
	if until, ok := laststop.StartHoldOffUntil(lastStopRecord(stop), configPath, now); ok {
		msg += ". The next try is at " + until.UTC().Format(time.RFC3339) + "."
	}
	return msg
}

func lastStopRecord(stop LastStop) laststop.LastStopFileRecord {
	return laststop.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}
}
