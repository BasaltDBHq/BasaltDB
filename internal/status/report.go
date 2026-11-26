package status

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
)

// Status is the status tool: whether the agent is served and each problem
// with its steps. It never fails on what it reads: an unreachable database
// or a missing guard is a problem in the result, not an error. It never
// names the credential file.
func (sc *Service) Status(ctx context.Context) (guidance.StatusReport, error) {
	return sc.statusDeps().report(ctx)
}

// statusDeps are what a status report reads: the Service's own in the
// engine, localStatus's for basalt status on an engine run as the person.
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
	update                    *guidance.UpdateInfo
	// engineKey is the engine id basalt status read from the running
	// engine's key file ("" when it is refused), nil when it reports no
	// engine record (localStatus.EngineKey); the engine uses vault.
	engineKey    *string
	engineRecord EngineRecordReader
	trust        TrustReporter
	cmds         guidance.Commands
	probe        Probe
	// watch is the agent's pending setup as this report reads it.
	watch    handoff.SetupWatch
	passkeys func(context.Context) ([]passkey.Credential, error)
	log      *slog.Logger
	now      func() time.Time
	// The host's: how errors map, the guard version this build installs and
	// the crash reports.
	errs         guidance.ErrorMap
	latestGuard  func() int
	crashReports func(dirs ...string) []CrashReport
	crashFile    func(dirs []string, id string) string
}

func (sc *Service) statusDeps() statusDeps {
	return statusDeps{
		name: sc.core.Name, operatedBy: sc.deps.OperatedBy, build: sc.deps.Build, startedBy: sc.deps.StartedBy, pagesBase: sc.core.PagesBase, pagesOrigin: sc.core.PagesOrigin,
		sameUser: sc.deps.SameUser, devLocalPages: sc.deps.DevLocalPages, connectBudget: sc.deps.ConnectBudget, engineReachable: true, vault: sc.deps.Vault, portal: sc.deps.Portal, plugins: sc.deps.Plugins,
		crashDirs: sc.deps.CrashDirs, linkBudget: sc.core.LinkBudget, access: sc.deps.Access,
		engineRecord: sc.deps.EngineRecord, trust: sc.deps.Trust, cmds: sc.core.Commands, probe: sc.deps.Probe, watch: sc.setupWatch(),
		errs: sc.core.Errors, latestGuard: sc.deps.LatestGuardVersion, crashReports: sc.deps.CrashReports, crashFile: sc.deps.CrashFile,
		update: sc.UpdateInfo(), passkeys: sc.deps.Passkeys.Passkeys, log: sc.core.Log, now: sc.core.Now,
	}
}

// localStatus is what basalt status reads for an agent whose engine runs as
// the person's own OS user (same-user mode): the config, the agent's own
// credential and whether the engine process runs. Its report is the status
// tool's, with engine.reachable from the process and ENGINE_UNREACHABLE
// when it does not run.
type localStatus struct {
	Name       string
	Commands   guidance.Commands
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
	// Errors maps a failure to the contract's tool error; LatestGuardVersion
	// is the basalt_meta version this build installs.
	Errors             guidance.ErrorMap
	LatestGuardVersion func() int
}

// report is the status report. It panics on a missing probe, passkey
// reader, logger or clock.
func (l localStatus) report(ctx context.Context) (guidance.StatusReport, error) {
	if l.Probe == nil || l.Passkeys == nil || l.Log == nil || l.Now == nil || l.LatestGuardVersion == nil {
		panic("agent: local status needs a probe, a passkey reader, a logger, a clock and the guard version")
	}
	base := l.PagesBase
	if base == "" {
		base = links.DefaultLocal
	}
	return statusDeps{
		name: l.Name, operatedBy: l.OperatedBy, build: buildinfo.Version, pagesBase: base, pagesOrigin: l.PagesOrigin,
		sameUser: true, devLocalPages: l.DevLocalPages, connectBudget: l.ConnectBudget, portal: l.Portal, engineReachable: l.EngineRunning, engineUnknown: l.EngineUnknown, cmds: l.Commands, probe: l.Probe,
		engineKey: l.EngineKey, engineRecord: l.EngineRecord, trust: l.Trust,
		// basalt status reads; the running engine finishes the setup.
		watch:    handoff.NewLocalWatch(l.Setup, l.Probe, l.Log, l.Now),
		passkeys: l.Passkeys, log: l.Log, now: l.Now,
		errs: l.Errors, latestGuard: l.LatestGuardVersion,
	}.report(ctx)
}

func (s statusDeps) report(ctx context.Context) (guidance.StatusReport, error) {
	s.cmds = s.cmds.OperatedBy(s.operatedBy)
	r := Head{
		Agent: s.name, OperatedBy: s.operatedBy, SameUser: s.sameUser, Build: s.build, StartedBy: s.startedBy,
		PagesBase: s.pagesBase, PagesOrigin: s.pagesOrigin, Vault: s.vault,
	}.report()
	r.Engine.Reachable, r.Update = s.engineReachable, s.update
	ps := guidance.Problems{Cmds: s.cmds, ConnectBudget: s.connectBudget}
	if s.devLocalPages {
		ps.Add(problemDevLocalPages, "the pages are development pages on this machine, not the portal",
			func(b *guidance.Steps) string { return devLocalPagesSteps(b, s.cmds) })
	}
	if !s.engineReachable && !s.engineUnknown {
		ps.Add(problemEngineUnreachable, "the engine is not running, so the agent's tools do not answer",
			func(b *guidance.Steps) string { return guidance.EngineUnreachableSteps(b, s.cmds, guidance.ToolStatus) })
	}
	s.addPortalProblem(&ps)
	s.addPluginProblems(&ps)
	var trust *TrustReport
	r.Trust, trust = s.trustStatus(ctx, &ps)
	setup, known := s.watch.View(ctx)
	r.Setup = setup.Status
	if path := s.watch.LockTroubleFile(); path != "" {
		ps.Add(problemLockFileUnusable, "the engine cannot open "+path+", so a finished setup is not written back",
			func(b *guidance.Steps) string { return handoff.LockFileSteps(b, path) })
	}
	if known {
		// A setup whose recorded state could not be read (the database is
		// down) gets no problem: the code may have been used already.
		setup.AddProblem(&ps)
	}

	st, err := s.probe.GuardStatus(ctx)
	// A pending INSTALL code explains a role that cannot log in or a guard
	// that is not there yet; any other failure is reported as it is.
	explained := known && setup.ExplainsGuard() && handoff.NotInstalledYet(st, err)
	switch {
	case err != nil:
		r.Guard = guidance.GuardStatus{State: guardmodel.GuardUnknown, Build: s.latestGuard()}
		if !explained {
			s.addUnreachable(ctx, &ps, err, trust)
		}
	default:
		r.Guard = guardStatusDTO(st)
		if !explained {
			addGuardProblem(&ps, st)
		}
	}
	if err == nil && st.State != guardmodel.GuardMissing {
		r.Passkeys = s.countPasskeys(ctx, &ps, setup.Status.State == handoff.SetupDone)
	}
	if err == nil {
		r.Ledger = s.ledgerStatus(ctx, st)
	}
	r.Crash, r.Plugins = s.crashStatus(), s.pluginHealth()
	if err == nil && st.State != guardmodel.GuardMissing {
		r.Access = s.accessStatus(ctx)
	}
	readable := err == nil && st.State != guardmodel.GuardMissing
	if readable {
		s.addReinstalled(ctx, &ps)
	}
	switch {
	case s.vault != nil && r.Vault != nil:
		r.EngineRecord = s.engineRecordStatus(ctx, r.Vault.EngineID, readable, &ps)
	case s.engineKey != nil:
		r.EngineRecord = s.engineRecordStatus(ctx, *s.engineKey, readable, &ps)
	}
	return finish(r, ps)
}

func configAgent(cfg *config.Config, name string) (config.Agent, bool) {
	for _, a := range cfg.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return config.Agent{}, false
}

// OperatedBy is the status enum of an engine.json operatedBy value: PERSON unless it is AGENT.
func OperatedBy(v string) string {
	if v == mcpcontract.OperatedByAgent {
		return v
	}
	return mcpcontract.OperatedByPerson
}

// Enforcement is GUARD_ONLY when the agent could use its credential
// directly: it operates the machine, or the engine runs as the person.
func Enforcement(operated string, sameUser bool) string {
	if operated == mcpcontract.OperatedByAgent || sameUser {
		return enforcementGuardOnly
	}
	return enforcementEngineAndGuard
}

// Ready is whether no problem of the list is an error.
func Ready(list []guidance.Problem) bool {
	for _, p := range list {
		if p.Severity == mcpcontract.SeverityError {
			return false
		}
	}
	return true
}

func guardStatusDTO(st guardmodel.Status) guidance.GuardStatus {
	out := guidance.GuardStatus{State: st.State, Build: st.Build, MissingBreaking: st.MissingBreaking, MissingNonBreaking: st.MissingNonBreaking}
	if st.State != guardmodel.GuardMissing {
		installed := st.Installed
		out.Installed = &installed
	}
	return out
}

// ledgerStatus is the ledger's size and retention. A missing guard has no
// ledger, and a size that cannot be read is logged and left out: it is
// never a problem.
func (s statusDeps) ledgerStatus(ctx context.Context, st guardmodel.Status) *guidance.LedgerStatus {
	if st.State == guardmodel.GuardMissing {
		return nil
	}
	n, err := s.probe.LedgerBytes(ctx)
	if err != nil {
		s.log.Debug("status: read the ledger size", "err", err)
		return nil
	}
	return &guidance.LedgerStatus{Bytes: n, ValuesKeptDays: ledgerValuesKeptDays, RecordsKeptDays: ledgerRecordsKeptDays}
}

// reinstalledAsk is LEDGER_REINSTALLED's ASK_PERSON step.
const reinstalledAsk = "Show the person this notice and ask whether someone on their team reinstalled Basalt. " +
	"The tools keep working, and the notice stays until an admin acknowledges it."

// addReinstalled is LEDGER_REINSTALLED when the ledger or the engine's kept
// copy records a reinstall. A guard older than version 36 records none; a
// read that fails is logged and adds nothing.
func (s statusDeps) addReinstalled(ctx context.Context, ps *guidance.Problems) {
	msg, ok, err := s.probe.ReinstallNotice(ctx, guidance.MaxPersonMessageLength)
	if err != nil {
		s.log.Error("status: read the reinstalls", "err", err)
		return
	}
	if !ok {
		return
	}
	ps.Add(problemLedgerReinstalled, "the guard was installed again and a pin of the old ledger was set aside; the tools keep working",
		func(b *guidance.Steps) string {
			b.AskPerson(reinstalledAsk)
			return msg
		})
}

// passkeys counts the active passkeys that can sign the agent's links:
// those registered on the origin of its pages (pagesPasskeys); none is
// NO_PASSKEY. A count that fails is logged and leaves active out.
func (s statusDeps) countPasskeys(ctx context.Context, ps *guidance.Problems, setupDone bool) guidance.PasskeysStatus {
	all, err := s.passkeys(ctx)
	if err != nil {
		s.log.Error("status: count passkeys", "err", err)
		return guidance.PasskeysStatus{}
	}
	keys, origin := passkey.OnPagesOrigin(all, s.pagesBase)
	n := len(keys)
	if n == 0 {
		msg := "no passkey is registered, so held writes and reverts cannot be signed"
		if len(all) > 0 {
			msg = "no passkey is registered on " + origin + ", where this agent's links open, so held writes and reverts cannot be signed"
		}
		ps.Add(problemNoPasskey, msg, func(b *guidance.Steps) string { return noPasskeyProblemSteps(b, s.cmds) })
	}
	out := guidance.PasskeysStatus{Registered: n > 0, Active: &n}
	for _, k := range keys {
		entry := guidance.PasskeyStatus{CredentialID: k.ID}
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
func passkeySummary(keys []guidance.PasskeyStatus) string {
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

// noPasskeyProblemSteps are the NO_PASSKEY problem's steps: the setup
// page's Update link when the engine serves it (its Update check adds a
// passkey on the person's device), else guidance.NoPasskeySteps.
func noPasskeyProblemSteps(b *guidance.Steps, cmds guidance.Commands) string {
	if !cmds.AgentOperated() && cmds.UpdateLinkURL() != "" {
		// The setup page's Update check adds a passkey on this device.
		b.OpenLink(cmds.UpdateLinkURL(), "Show the person this link: its page adds a passkey on their device.")
		b.EndTurn("End your turn; the person adds the passkey on that page.")
		return guidance.NothingSignableLead + " Open the link the agent gives you and add a passkey there."
	}
	return guidance.NoPasskeySteps(b, cmds)
}
