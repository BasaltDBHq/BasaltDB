package status

import (
	"context"
	"fmt"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// addUnreachable is the problem of a guard read that failed: the database
// refused the credential, or cannot be reached.
func (s statusDeps) addUnreachable(ctx context.Context, ps *guidance.Problems, err error, trust *TrustReport) {
	if trustprofile.CertificateNotVerified(err) {
		s.addCertificateNotVerified(ctx, ps, err, trust)
		return
	}
	te := s.errs.ToolError(err)
	switch te.Reason {
	case guidance.ReasonCredentialRejected:
		ps.Add(problemCredentialRejected, "the database refuses the agent's credential",
			func(b *guidance.Steps) string { return guidance.FixSteps(b, s.cmds, guidance.ReasonCredentialRejected) })
	case guidance.ReasonTooManyConnections:
		ps.Add(problemTooManyConnections, "the agent's role has used all the database connections it is allowed",
			func(b *guidance.Steps) string {
				b.AskPerson(guidance.TooManyConnectionsAsk)
				return guidance.TooManyConnectionsMessage(s.cmds)
			})
	case guidance.ReasonGuardMissing:
		ps.Add(problemGuardMissing, "the guard is not installed in this database",
			func(b *guidance.Steps) string { return guidance.FixSteps(b, s.cmds, guidance.ReasonGuardMissing) })
	default:
		s.log.Error("status: read the guard", "err", err)
		ps.Add(problemDatabaseUnreachable, "the database cannot be reached",
			func(b *guidance.Steps) string {
				b.AskPerson("Tell the person the database cannot be reached and ask them to check that Postgres is running.")
				return guidance.DatabaseUnreachableMessage
			})
	}
}

func addGuardProblem(ps *guidance.Problems, st guardmodel.Status) {
	switch st.State {
	case guardmodel.GuardMissing:
		ps.Add(problemGuardMissing, "the guard is not installed in this database; no tool but status works",
			func(b *guidance.Steps) string { return guidance.FixSteps(b, ps.Cmds, guidance.ReasonGuardMissing) })
	case guardmodel.GuardOutdated:
		ps.Add(problemGuardOutdated, fmt.Sprintf("the guard misses breaking migrations %s; no tool but status works until it is upgraded", versions(st.MissingBreaking)),
			func(b *guidance.Steps) string { return guidance.FixSteps(b, ps.Cmds, guidance.ReasonGuardOutdated) })
	case guardmodel.GuardUpgradeAvailable:
		ps.Add(problemUpgradeAvailable, fmt.Sprintf("the guard misses non-breaking migrations %s; every tool works", versions(st.MissingNonBreaking)),
			func(b *guidance.Steps) string { return upgradeSteps(b, ps.Cmds) })
	}
}

func versions(vs []int) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}

// --- admission ---

// Admit refuses a tool call the agent cannot be served yet (CONTRACT.md,
// Next steps, Startup failures): its INSTALL setup code has not run, or
// the guard is not installed or misses a breaking migration. It reads the
// guard on every call, so a guard update needs no engine restart. status is
// never refused.
func (sc *Service) Admit(ctx context.Context) error {
	if v, known := sc.setupWatch().Gate(ctx); known && v.Blocks() {
		return &guidance.SetupError{Code: v.Code, Fingerprint: v.Fingerprint, Expired: v.Status.State == handoff.SetupExpired, ConnectOnly: v.Status.ConnectOnly}
	}
	st, err := sc.deps.Probe.GuardStatus(ctx)
	if err != nil {
		return err
	}
	switch st.State {
	case guardmodel.GuardOutdated:
		return &toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonGuardOutdated, Message: fmt.Sprintf(
			"the guard in this database misses breaking migrations %s of this engine; only status works until the person upgrades it",
			versions(st.MissingBreaking))}
	case guardmodel.GuardMissing:
		return &toolresult.ToolError{
			Code: guidance.CodeUnavailable, Reason: guidance.ReasonGuardMissing,
			Message: "the guard is not installed in this database; only status works until the person installs it",
		}
	}
	return nil
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
