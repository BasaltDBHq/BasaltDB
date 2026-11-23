package handoff

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// setupView is the agent's setup from the laptop as status reports it.
type setupView struct {
	Status guidance.SetupStatus
	// code and fingerprint are the pending code's while it is still live
	// (status shows the fingerprint only while pending). An expired code
	// is never reprinted, including during the collect-window hold.
	Code, Fingerprint string
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
func (v setupView) ExplainsGuard() bool {
	return !v.confirmed && v.Status.Kind == guardmodel.SetupInstall && (v.Status.State == SetupPending || v.Status.State == SetupExpired)
}

// blocks reports whether the pending setup holds every tool but status: an
// INSTALL code that has not run, or a connect-only code whose database the
// person confirmed and that the database does not record yet.
func (v setupView) Blocks() bool {
	return v.ExplainsGuard() || (v.confirmed && v.Status.State == SetupPending)
}

func (v setupView) AddProblem(ps *guidance.Problems) {
	switch {
	case v.refused:
		ps.Add(ProblemDatabaseRefused, "the person said the database the setup reached is not theirs; a new setup code is needed",
			func(b *guidance.Steps) string { return databaseRefusedSteps(b, ps.Cmds) })
	case v.Status.State == SetupExpired:
		ps.Add(ProblemSetupExpired, "the agent's setup code expired before it was used; a new one is needed",
			func(b *guidance.Steps) string { return guidance.SetupExpiredSteps(b, ps.Cmds) })
	case v.Status.State != SetupPending:
	case v.awaiting:
		ps.AddLinked(ProblemSetupNotRun, connectOnlyWaitingMessage(v.Code),
			func(b *guidance.Steps) (string, []toolresult.Link) {
				return connectOnlySteps(b, v.Code, v.Fingerprint, ps.ConnectBudget)
			})
	case v.confirmed:
		ps.Add(ProblemSetupNotFound, "the database the person confirmed does not record this setup: "+v.database,
			func(b *guidance.Steps) string { return setupNotFoundSteps(b, ps.Cmds, v.database) })
	case v.Status.Kind == guardmodel.SetupInstall:
		ps.AddLinked(ProblemSetupNotRun, "the agent's setup has not run yet; no tool but status works until it has",
			func(b *guidance.Steps) (string, []toolresult.Link) {
				return guidance.SetupPendingSteps(b, ps.Cmds, v.Code, v.Fingerprint, true, ps.ConnectBudget)
			})
	default:
		ps.AddLinked(ProblemSetupChangePending, "a setup change is waiting for the person; the tools keep working as installed",
			func(b *guidance.Steps) (string, []toolresult.Link) {
				return guidance.SetupPendingSteps(b, ps.Cmds, v.Code, v.Fingerprint, false, ps.ConnectBudget)
			})
	}
}

// view reads the agent's setup: its pending code from the config unless
// it is recorded, else its latest recorded setup. known is false when the
// database cannot tell whether the pending code was used (see
// pendingRecorded); the config's code is then shown, with no problem.
func (s SetupWatch) View(ctx context.Context) (setupView, bool) {
	recorded, known := false, true
	if s.Setup != nil {
		recorded, known = s.PendingRecorded(ctx)
	}
	v := SetupFrom(s.Setup, recorded, s.Now())
	v.database = s.Database
	if v.Status.State != SetupNone || !known {
		return v, known
	}
	latest, ok, err := s.Probe.LatestSetup(ctx)
	if err != nil {
		s.Log.Error("status: read the latest setup", "err", err)
	}
	if ok {
		v.Status = guidance.SetupStatus{State: SetupDone, SetupID: latest.SetupID.String(), Kind: latest.Kind}
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
func SetupFrom(p *config.Setup, recorded bool, now time.Time) setupView {
	if p == nil || recorded {
		return setupView{Status: guidance.SetupStatus{State: SetupNone}}
	}
	connectOnly := connectOnlyCode(p.Code)
	if p.Refused {
		return setupView{refused: true, Status: guidance.SetupStatus{State: SetupRefused, SetupID: p.SetupID, Kind: p.Kind, ConnectOnly: true}}
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
		return setupView{Status: guidance.SetupStatus{State: SetupNone}}
	}
	v := setupView{
		Code: p.Code, Fingerprint: p.Fingerprint, awaiting: p.AwaitingAddress, confirmed: confirmed,
		Status: guidance.SetupStatus{State: SetupPending, SetupID: p.SetupID, Kind: p.Kind, ExpiresAt: p.ExpiresAt, Fingerprint: p.Fingerprint, ConnectOnly: connectOnly},
	}
	if expired {
		v.Status.State, v.Status.Fingerprint = SetupExpired, ""
	}
	if err == nil && !now.Before(expires) {
		// An expired code is never reprinted, even while we still collect.
		v.Code, v.Fingerprint, v.Status.Fingerprint = "", "", ""
	}
	return v
}

// connectOnlyCode reports whether code is a connect-only setup code (it
// has no target). A code that cannot be read is not.
func connectOnlyCode(code string) bool {
	p, err := setupcode.Decode(code)
	return err == nil && p.ConnectOnly()
}

// gate is the pending setup a call checks: none without a pending
// INSTALL code, so an agent without one reads nothing more. known is false
// when the database cannot tell whether the code was used.
func (s SetupWatch) Gate(ctx context.Context) (setupView, bool) {
	if s.Setup == nil || (s.Setup.Kind != guardmodel.SetupInstall && !connectOnlyCode(s.Setup.Code)) {
		return setupView{Status: guidance.SetupStatus{State: SetupNone}}, true
	}
	now := s.Now()
	if s.NotRecorded.fresh(s.Setup.SetupID, now) {
		return SetupFrom(s.Setup, false, now), true
	}
	recorded, known := s.PendingRecorded(ctx)
	if known && !recorded {
		s.NotRecorded.remember(s.Setup.SetupID, now)
	}
	return SetupFrom(s.Setup, recorded, now), known
}

// pendingRecorded reads whether the pending setup code was used. A database
// that refuses the agent's role or has no guard yet means it was not (an
// INSTALL code makes both); any other failure, such as a database that
// cannot be reached, leaves it unknown (known false), logged.
func (s SetupWatch) PendingRecorded(ctx context.Context) (recorded, known bool) {
	id, err := uuid.Parse(s.Setup.SetupID)
	if err == nil {
		recorded, err = s.recordedAsAgent(ctx, id)
	}
	switch {
	case err == nil:
		return recorded, true
	case NotInstalledYet(guardmodel.Status{}, err):
		return false, true
	}
	s.Log.Error("read the pending setup", "err", err)
	return false, false
}

// notInstalledYet reports whether a guard read (st, or the error it failed
// with) shows what a pending INSTALL code explains: the agent's role cannot
// log in yet, or the guard is not there yet.
func NotInstalledYet(st guardmodel.Status, err error) bool {
	if err == nil {
		return st.State == guardmodel.GuardMissing
	}
	// Only the store's own refusals carry these reasons, so no adapter's error
	// values are needed to tell them.
	reason := guidance.ErrorMap{}.ToolError(err).Reason
	return reason == guidance.ReasonCredentialRejected || reason == guidance.ReasonGuardMissing
}
