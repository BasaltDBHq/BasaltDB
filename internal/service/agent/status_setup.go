package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// addUnreachable is the problem of a guard read that failed: the database
// refused the credential, or cannot be reached.
func (s statusDeps) addUnreachable(ctx context.Context, ps *Problems, err error, trust *TrustReport) {
	if trustprofile.CertificateNotVerified(err) {
		s.addCertificateNotVerified(ctx, ps, err, trust)
		return
	}
	te := s.errs.ToolError(err)
	switch te.Reason {
	case reasonCredentialRejected:
		ps.Add(problemCredentialRejected, "the database refuses the agent's credential",
			func(b *Steps) string { return fixSteps(b, s.cmds, reasonCredentialRejected) })
	case reasonTooManyConnections:
		ps.Add(problemTooManyConnections, "the agent's role has used all the database connections it is allowed",
			func(b *Steps) string {
				b.AskPerson(tooManyConnectionsAsk)
				return tooManyConnectionsMessage(s.cmds)
			})
	case reasonGuardMissing:
		ps.Add(problemGuardMissing, "the guard is not installed in this database",
			func(b *Steps) string { return fixSteps(b, s.cmds, reasonGuardMissing) })
	default:
		s.log.Error("status: read the guard", "err", err)
		ps.Add(problemDatabaseUnreachable, "the database cannot be reached",
			func(b *Steps) string {
				b.AskPerson("Tell the person the database cannot be reached and ask them to check that Postgres is running.")
				return databaseUnreachableMessage
			})
	}
}

func addGuardProblem(ps *Problems, st guardmodel.Status) {
	switch st.State {
	case guardmodel.GuardMissing:
		ps.Add(problemGuardMissing, "the guard is not installed in this database; no tool but status works",
			func(b *Steps) string { return fixSteps(b, ps.Cmds, reasonGuardMissing) })
	case guardmodel.GuardOutdated:
		ps.Add(problemGuardOutdated, fmt.Sprintf("the guard misses breaking migrations %s; no tool but status works until it is upgraded", versions(st.MissingBreaking)),
			func(b *Steps) string { return fixSteps(b, ps.Cmds, reasonGuardOutdated) })
	case guardmodel.GuardUpgradeAvailable:
		ps.Add(problemUpgradeAvailable, fmt.Sprintf("the guard misses non-breaking migrations %s; every tool works", versions(st.MissingNonBreaking)),
			func(b *Steps) string { return upgradeSteps(b, ps.Cmds) })
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
	return !v.confirmed && v.status.Kind == guardmodel.SetupInstall && (v.status.State == setupPending || v.status.State == setupExpired)
}

// blocks reports whether the pending setup holds every tool but status: an
// INSTALL code that has not run, or a connect-only code whose database the
// person confirmed and that the database does not record yet.
func (v setupView) blocks() bool {
	return v.explainsGuard() || (v.confirmed && v.status.State == setupPending)
}

func (v setupView) addProblem(ps *Problems) {
	switch {
	case v.refused:
		ps.Add(problemDatabaseRefused, "the person said the database the setup reached is not theirs; a new setup code is needed",
			func(b *Steps) string { return databaseRefusedSteps(b, ps.Cmds) })
	case v.status.State == setupExpired:
		ps.Add(problemSetupExpired, "the agent's setup code expired before it was used; a new one is needed",
			func(b *Steps) string { return setupExpiredSteps(b, ps.Cmds) })
	case v.status.State != setupPending:
	case v.awaiting:
		ps.AddLinked(problemSetupNotRun, connectOnlyWaitingMessage(v.code),
			func(b *Steps) (string, []toolresult.Link) {
				return connectOnlySteps(b, v.code, v.fingerprint, ps.ConnectBudget)
			})
	case v.confirmed:
		ps.Add(problemSetupNotFound, "the database the person confirmed does not record this setup: "+v.database,
			func(b *Steps) string { return setupNotFoundSteps(b, ps.Cmds, v.database) })
	case v.status.Kind == guardmodel.SetupInstall:
		ps.AddLinked(problemSetupNotRun, "the agent's setup has not run yet; no tool but status works until it has",
			func(b *Steps) (string, []toolresult.Link) {
				return setupPendingSteps(b, ps.Cmds, v.code, v.fingerprint, true, ps.ConnectBudget)
			})
	default:
		ps.AddLinked(problemSetupChangePending, "a setup change is waiting for the person; the tools keep working as installed",
			func(b *Steps) (string, []toolresult.Link) {
				return setupPendingSteps(b, ps.Cmds, v.code, v.fingerprint, false, ps.ConnectBudget)
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
// finished after expiresAt, and so does an AGENT code marked
// certificateChanged; the expired code is not reprinted.
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
	// Still collecting during the hold after the code expires: for its
	// address, or, for a changed certificate, for the certificate the person
	// trusted on the connect page.
	collecting := (connectOnly && p.AwaitingAddress) || p.CertificateChanged
	hold := collecting && err == nil && now.Before(expires.Add(setupcode.CollectWindow-setupcode.Lifetime))
	if expired && hold {
		expired = false
	}
	if expired && p.Kind != guardmodel.SetupInstall && !p.AwaitingAddress {
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
	st, err := s.deps.Status.Probe.GuardStatus(ctx)
	if err != nil {
		return err
	}
	switch st.State {
	case guardmodel.GuardOutdated:
		return &toolresult.ToolError{Code: CodeUnavailable, Reason: reasonGuardOutdated, Message: fmt.Sprintf(
			"the guard in this database misses breaking migrations %s of this engine; only status works until the person upgrades it",
			versions(st.MissingBreaking))}
	case guardmodel.GuardMissing:
		return &toolresult.ToolError{
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
	if s.setup == nil || (s.setup.Kind != guardmodel.SetupInstall && !connectOnlyCode(s.setup.Code)) {
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
	case notInstalledYet(guardmodel.Status{}, err):
		return false, true
	}
	s.log.Error("read the pending setup", "err", err)
	return false, false
}

// notInstalledYet reports whether a guard read (st, or the error it failed
// with) shows what a pending INSTALL code explains: the agent's role cannot
// log in yet, or the guard is not there yet.
func notInstalledYet(st guardmodel.Status, err error) bool {
	if err == nil {
		return st.State == guardmodel.GuardMissing
	}
	// Only the store's own refusals carry these reasons, so no adapter's error
	// values are needed to tell them.
	reason := ErrorMap{}.ToolError(err).Reason
	return reason == reasonCredentialRejected || reason == reasonGuardMissing
}

// guardUpgrade answers UpgradeChecker from the probe.
type guardUpgrade struct{ probe Probe }

func (g guardUpgrade) UpgradeAvailable(ctx context.Context) (bool, error) {
	st, err := g.probe.GuardStatus(ctx)
	if err != nil {
		return false, err
	}
	return st.State == guardmodel.GuardUpgradeAvailable, nil
}
