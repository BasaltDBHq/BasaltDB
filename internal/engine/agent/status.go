package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// The status tool (CONTRACT.md, MCP tools, status; api/mcp/tools/status.json).
// The engine answers it with what it reads from the agent's database; the
// shim answers it with EngineDownStatus when the engine socket does not.

const toolStatus = "status"

// Problem codes of the status tool (api/mcp/errors/next-steps.json, problems).
const (
	problemEngineUnreachable   = reasonEngineUnreachable
	problemDatabaseUnreachable = reasonDatabaseUnreachable
	problemCredentialRejected  = reasonCredentialRejected
	problemGuardMissing        = reasonGuardMissing
	problemGuardOutdated       = reasonGuardOutdated
	problemUpgradeAvailable    = "GUARD_UPGRADE_AVAILABLE"
	problemNoPasskey           = "NO_PASSKEY"
	problemSetupNotRun         = "SETUP_NOT_RUN"
	problemSetupExpired        = "SETUP_EXPIRED"
	problemSetupChangePending  = "SETUP_CHANGE_PENDING"
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
	Problems    []Problem      `json:"problems"`
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
	r := StatusReport{
		Agent: s.Name, OperatedBy: operatedBy(s.OperatedBy), Enforcement: enforcement(s.OperatedBy, s.SameUser),
		Engine: EngineStatus{Reachable: true, Build: s.Build},
		Pages:  PagesStatus{Served: s.PagesOrigin != "", URL: s.PagesBase},
	}
	if s.Vault != nil {
		v := s.Vault.VaultStatus()
		r.Vault = &v
	}
	ps := problems{cmds: s.Commands}
	setup := s.setupView(ctx)
	r.Setup = setup.status
	setup.addProblem(&ps)

	st, err := s.Probe.GuardStatus(ctx)
	switch {
	case err != nil:
		r.Guard = GuardStatus{State: guard.GuardUnknown, Build: guard.LatestVersion()}
		if !setup.explainsGuard() {
			s.addUnreachable(&ps, err)
		}
	default:
		r.Guard = guardStatusDTO(st)
		if !setup.explainsGuard() {
			addGuardProblem(&ps, st)
		}
	}
	if err == nil && st.State != guard.GuardMissing {
		r.Passkeys = s.passkeys(ctx, &ps)
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
	ps := problems{cmds: cmds}
	ps.add(problemEngineUnreachable, "the engine does not answer, so no tool but status works",
		func(b *Steps) string { return engineUnreachableSteps(b, cmds) })
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

// passkeys counts the active passkeys; none is NO_PASSKEY. A count that
// fails is logged and leaves active out.
func (s *Service) passkeys(ctx context.Context, ps *problems) PasskeysStatus {
	keys, err := s.Approvals.Passkeys(ctx)
	if err != nil {
		s.Log.Error("status: count passkeys", "err", err)
		return PasskeysStatus{}
	}
	n := len(keys)
	if n == 0 {
		cmd := s.Commands.Init("--add-passkey")
		ps.add(problemNoPasskey, "no passkey is registered, so held writes and reverts cannot be signed",
			func(b *Steps) string {
				b.RunCommand(cmd, "Register a passkey: held writes and reverts are signed with one.")
				return "No passkey is registered for this agent, so nothing it holds for you can be approved yet. Run: " + cmd
			})
	}
	return PasskeysStatus{Registered: n > 0, Active: &n}
}

// addUnreachable is the problem of a guard read that failed: the database
// refused the credential, or cannot be reached.
func (s *Service) addUnreachable(ps *problems, err error) {
	te := ToolError(err)
	switch te.Reason {
	case reasonCredentialRejected:
		ps.add(problemCredentialRejected, "the database refuses the agent's credential",
			func(b *Steps) string { return fixSteps(b, s.Commands, reasonCredentialRejected) })
	case reasonGuardMissing:
		ps.add(problemGuardMissing, "the guard is not installed in this database",
			func(b *Steps) string { return fixSteps(b, s.Commands, reasonGuardMissing) })
	default:
		s.Log.Error("status: read the guard", "err", err)
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
	code   string
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
			func(b *Steps) string { return setupPendingSteps(b, ps.cmds, v.code, true) })
	default:
		ps.add(problemSetupChangePending, "a setup change is waiting for the person; the tools keep working as installed",
			func(b *Steps) string { return setupPendingSteps(b, ps.cmds, v.code, false) })
	}
}

// setupView reads the agent's setup: its pending code from the config unless
// it is recorded, else its latest recorded setup. A read that fails is
// logged and treated as nothing recorded.
func (s *Service) setupView(ctx context.Context) setupView {
	recorded := false
	if s.Setup != nil {
		id, err := uuid.Parse(s.Setup.SetupID)
		if err == nil {
			recorded, err = s.Probe.SetupRecorded(ctx, id)
		}
		if err != nil {
			s.Log.Error("status: read the pending setup", "err", err)
		}
	}
	v := setupFrom(s.Setup, recorded, s.Now())
	if v.status.State != setupNone {
		return v
	}
	latest, ok, err := s.Probe.LatestSetup(ctx)
	if err != nil {
		s.Log.Error("status: read the latest setup", "err", err)
	}
	if ok {
		v.status = SetupStatus{State: setupDone, SetupID: latest.SetupID.String(), Kind: latest.Kind}
	}
	return v
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
	v := setupView{code: p.Code, status: SetupStatus{State: setupPending, SetupID: p.SetupID, Kind: p.Kind, ExpiresAt: p.ExpiresAt, Fingerprint: p.Fingerprint}}
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
	if v := s.setupGate(ctx); v.explainsGuard() {
		return &SetupError{Code: v.code, Expired: v.status.State == setupExpired}
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
		return &mcp.ToolError{Code: CodeUnavailable, Reason: reasonGuardMissing,
			Message: "the guard is not installed in this database; only status works until the person installs it"}
	}
	return nil
}

// setupGate is the pending setup a call checks: none without a pending
// INSTALL code, so an agent without one reads nothing more.
func (s *Service) setupGate(ctx context.Context) setupView {
	if s.Setup == nil || s.Setup.Kind != guard.SetupInstall {
		return setupView{status: SetupStatus{State: setupNone}}
	}
	recorded := false
	if id, err := uuid.Parse(s.Setup.SetupID); err == nil {
		if recorded, err = s.Probe.SetupRecorded(ctx, id); err != nil {
			recorded = false
		}
	}
	return setupFrom(s.Setup, recorded, s.Now())
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
