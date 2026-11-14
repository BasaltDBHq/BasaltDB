package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
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
	problemEngineRevoked       = "ENGINE_REVOKED"
	problemDirectNotServed     = "DIRECT_NOT_SERVED"
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

// DBProbe is the Probe on an agent connection or pool, against the build's
// migrations (guard.Migrations outside tests).
type DBProbe struct {
	Q          guard.Querier
	Migrations []guard.Migration
}

// GuardStatus reads schema_version.
func (p DBProbe) GuardStatus(ctx context.Context) (guard.Status, error) {
	return guard.AgentStatus(ctx, p.Q, p.Migrations)
}

// SetupRecorded reports whether setup id is recorded.
func (p DBProbe) SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, p.Q, id)
}

// LatestSetup is the agent's newest recorded setup.
func (p DBProbe) LatestSetup(ctx context.Context) (guard.AgentSetup, bool, error) {
	return guard.LatestAgentSetup(ctx, p.Q)
}

// LedgerBytes is the size of basalt_meta.
func (p DBProbe) LedgerBytes(ctx context.Context) (int64, error) {
	return guard.LedgerBytes(ctx, p.Q)
}

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

// StatusReport is the status tool's result.
// EngineRecordStatus is status.engineRecord: this engine's key as the
// agent's database records it (CONTRACT.md, Direct transport).
type EngineRecordStatus struct {
	State      string `json:"state"`
	URL        string `json:"url,omitempty"`
	RecordedAt string `json:"recordedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

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
	Problems     []Problem           `json:"problems"`
}

// EngineStatus is status.engine.
type EngineStatus struct {
	Reachable bool   `json:"reachable"`
	Build     string `json:"build,omitempty"`
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
	Code          string     `json:"code"`
	Severity      string     `json:"severity"`
	Message       string     `json:"message"`
	PersonMessage string     `json:"personMessage,omitempty"`
	NextSteps     []NextStep `json:"nextSteps"`
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
	pagesBase, pagesOrigin    string
	sameUser, engineReachable bool
	engineUnknown             bool
	devLocalPages             bool
	vault                     VaultReporter
	engineRecord              EngineRecordReader
	directServed              bool
	cmds                      Commands
	setup                     *config.Setup
	probe                     Probe
	finisher                  SetupFinisher
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
		name: s.Name, operatedBy: s.OperatedBy, build: s.Build, pagesBase: s.PagesBase, pagesOrigin: s.PagesOrigin,
		sameUser: s.SameUser, devLocalPages: s.DevLocalPages, engineReachable: true, vault: s.Vault,
		engineRecord: s.EngineRecord, directServed: s.DirectServed, cmds: s.Commands, setup: s.pendingSetup(), probe: s.Probe,
		finisher: s.Finisher, finished: s.setupFinished, notRecorded: &s.notRecorded, lockTrouble: &s.lockTrouble, passkeys: s.Approvals.Passkeys, log: s.Log, now: s.Now,
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
	Probe         Probe
	Passkeys      func(context.Context) ([]passkey.Credential, error)
	Log           *slog.Logger
	Now           func() time.Time
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
		sameUser: true, devLocalPages: l.DevLocalPages, engineReachable: l.EngineRunning, engineUnknown: l.EngineUnknown, cmds: l.Commands, setup: l.Setup, probe: l.Probe,
		// basalt status reads; the running engine finishes the setup.
		finisher: noFinisher{}, finished: func(string) {}, notRecorded: &setupCache{}, lockTrouble: &lockTrouble{}, passkeys: l.Passkeys, log: l.Log, now: l.Now,
	}.report(ctx)
}

func (s statusDeps) report(ctx context.Context) (StatusReport, error) {
	s.cmds = s.cmds.OperatedBy(s.operatedBy)
	r := StatusReport{
		Agent: s.name, OperatedBy: operatedBy(s.operatedBy), Enforcement: enforcement(s.operatedBy, s.sameUser),
		Engine: EngineStatus{Reachable: s.engineReachable, Build: s.build},
		Pages:  PagesStatus{Served: s.pagesOrigin != "", URL: s.pagesBase},
	}
	if s.vault != nil {
		v := s.vault.VaultStatus()
		r.Vault = &v
	}
	ps := problems{cmds: s.cmds}
	if s.devLocalPages {
		ps.add(problemDevLocalPages, "the pages are development pages on this machine, not the portal",
			func(b *Steps) string { return devLocalPagesSteps(b, s.cmds) })
	}
	if !s.engineReachable && !s.engineUnknown {
		ps.add(problemEngineUnreachable, "the engine is not running, so the agent's tools do not answer",
			func(b *Steps) string { return engineUnreachableSteps(b, s.cmds, toolStatus) })
	}
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
			s.addUnreachable(&ps, err)
		}
	default:
		r.Guard = guardStatusDTO(st)
		if !explained {
			addGuardProblem(&ps, st)
		}
	}
	if err == nil && st.State != guard.GuardMissing {
		r.Passkeys = s.countPasskeys(ctx, &ps)
	}
	if err == nil {
		r.Ledger = s.ledgerStatus(ctx, st)
	}
	if s.vault != nil && r.Vault != nil {
		r.EngineRecord = s.engineRecordStatus(ctx, r.Vault.EngineID, err == nil && st.State != guard.GuardMissing, &ps)
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
func EngineDownStatus(name string, cmds Commands, cfg *config.Config, build string, now time.Time) (StatusReport, error) {
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
	ps.add(problemEngineUnreachable, "the engine does not answer, so no tool but status works",
		func(b *Steps) string { return engineUnreachableSteps(b, cmds, toolStatus) })
	if cfg != nil {
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

// passkeys counts the active passkeys; none is NO_PASSKEY. A count that
// fails is logged and leaves active out.
func (s statusDeps) countPasskeys(ctx context.Context, ps *problems) PasskeysStatus {
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
	return PasskeysStatus{Registered: n > 0, Active: &n}
}

// noPasskeySteps: the person registers a passkey; on an agent-operated
// engine, with a setup code the agent makes (RI-6: the person's computer
// registers a portal passkey when none is active).
func noPasskeySteps(b *Steps, cmds Commands) string {
	const lead = "No passkey is registered for this agent, so nothing it holds for you can be approved yet."
	if cmds.AgentOperated() {
		return remoteSetupSteps(b, cmds, "", lead)
	}
	cmd := cmds.Init("--add-passkey")
	b.RunCommand(cmd, "Register a passkey: held writes and reverts are signed with one.")
	return lead + " Run: " + cmd
}

// addUnreachable is the problem of a guard read that failed: the database
// refused the credential, or cannot be reached.
func (s statusDeps) addUnreachable(ps *problems, err error) {
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
	// code and fingerprint are the pending code's, also once it expired
	// (status shows the fingerprint only while pending).
	code, fingerprint string
}

// explainsGuard reports whether an INSTALL setup is pending or expired: the
// guard and the agent's role are not there yet, so the setup problem is
// the one to fix and the guard and database problems it causes are left out.
func (v setupView) explainsGuard() bool {
	return v.status.Kind == guard.SetupInstall && (v.status.State == setupPending || v.status.State == setupExpired)
}

func (v setupView) addProblem(ps *problems) {
	switch {
	case v.status.State == setupExpired:
		ps.add(problemSetupExpired, "the agent's setup code expired before it was used; a new one is needed",
			func(b *Steps) string { return setupExpiredSteps(b, ps.cmds) })
	case v.status.State != setupPending:
	case v.status.Kind == guard.SetupInstall:
		ps.add(problemSetupNotRun, "the agent's setup has not run yet; no tool but status works until it has",
			func(b *Steps) string { return setupPendingSteps(b, v.code, v.fingerprint, true) })
	default:
		ps.add(problemSetupChangePending, "a setup change is waiting for the person; the tools keep working as installed",
			func(b *Steps) string { return setupPendingSteps(b, v.code, v.fingerprint, false) })
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
// (NONE here), as is a recorded one.
func setupFrom(p *config.Setup, recorded bool, now time.Time) setupView {
	if p == nil || recorded {
		return setupView{status: SetupStatus{State: setupNone}}
	}
	expires, err := p.Expires()
	expired := err != nil || !now.Before(expires)
	if expired && p.Kind != guard.SetupInstall {
		return setupView{status: SetupStatus{State: setupNone}}
	}
	v := setupView{code: p.Code, fingerprint: p.Fingerprint, status: SetupStatus{State: setupPending, SetupID: p.SetupID, Kind: p.Kind, ExpiresAt: p.ExpiresAt, Fingerprint: p.Fingerprint}}
	if expired {
		v.status.State, v.status.Fingerprint = setupExpired, ""
	}
	return v
}

// problems collects status problems, each built from its catalog entry.
type problems struct {
	cmds Commands
	list []Problem
	err  error
}

// add builds the problem code with the steps steps returns along with the
// person's message.
func (ps *problems) add(code, message string, steps func(*Steps) string) {
	entry, ok := problemEntry(code)
	if !ok {
		ps.fail(fmt.Errorf("no catalog entry for status problem %s", code))
		return
	}
	b := NewSteps()
	person := steps(b)
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
	ps.list = append(ps.list, Problem{Code: code, Severity: entry.Severity, Message: message, PersonMessage: person, NextSteps: list})
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
// guard on every call, so basalt upgrade needs no engine restart. status is
// never refused.
func (s *Service) Admit(ctx context.Context) error {
	if v, known := s.statusDeps().setupGate(ctx); known && v.explainsGuard() {
		return &SetupError{Code: v.code, Fingerprint: v.fingerprint, Expired: v.status.State == setupExpired}
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
	if s.setup == nil || s.setup.Kind != guard.SetupInstall {
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
// problems: ENGINE_REVOKED, and DIRECT_NOT_SERVED when the database records
// an address the engine has no direct listener for. Without the engine's
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
	if e.URL != nil {
		out.URL = *e.URL
	}
	switch {
	case e.RevokedAt != nil:
		out.State, out.RevokedAt = engineRevoked, e.RevokedAt.UTC().Format(time.RFC3339)
		ps.add(problemEngineRevoked, "the agent's database revoked this engine's key: its portal links stop working and its portal sessions are refused",
			engineRevokedSteps)
	case out.URL != "" && !s.directServed:
		ps.add(problemDirectNotServed, "the agent's database records an address for this engine, but directAddr is off, so a tunnel has nothing to forward to",
			func(b *Steps) string { return directNotServedSteps(b, ps.cmds, out.URL) })
	}
	return out
}

// engineRevokedSteps: the agent asks whether the person revoked this engine
// on purpose. Until a new key is recorded the agent hands over long links.
func engineRevokedSteps(b *Steps) string {
	b.AskPerson("Tell the person this engine's key is revoked in their database, so portal links stop working. Ask whether they revoked it on purpose, and show the message.")
	b.EndTurn("End your turn: the person answers next.")
	return "This engine's key is revoked in your database. Its portal links stop working; approvals go on through long links. " +
		"Did you revoke it on purpose? If you replaced the engine, the agent makes a new key with basalt engine rotate-key and gives you a new setup code."
}

// directNotServedAddr is the loopback address the step suggests for
// directAddr.
const directNotServedAddr = "127.0.0.1:8787"

// directNotServedSteps: set directAddr on the engine's machine, then
// restart the engine, so the person's tunnel has a listener to forward to.
func directNotServedSteps(b *Steps, cmds Commands, url string) string {
	command := cmds.InitRemote("--direct-addr " + directNotServedAddr)
	b.MachineCommand(cmds, command,
		"On the engine's machine, run this to set the address your tunnel forwards to, then restart the engine.",
		"Run this to set the engine's direct address, then restart the engine and call status again.")
	host := strings.TrimPrefix(url, "https://")
	if cmds.AgentOperated() {
		return "Your database records " + host + " for this engine, but the engine has no listener for your tunnel to forward to. " +
			"The agent sets one on its machine and restarts the engine; follow what it shows you next."
	}
	return "Your database records " + host + " for this engine, but the engine has no listener for your tunnel to forward to. " +
		"On the engine's machine, run this, then restart the engine: " + command
}
