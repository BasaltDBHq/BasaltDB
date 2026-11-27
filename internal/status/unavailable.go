package status

import (
	"errors"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// UnavailableSteps builds the steps and the person's message of an
// UNAVAILABLE error: a database the engine cannot reach is retried once; the
// machine problems are the person's to fix, with the command for it.
func (sc *Service) UnavailableSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	switch te.Reason {
	case guidance.ReasonDatabaseUnreachable:
		b.RepeatCall(f.Tool, nil, 0, "Try the same call once more, in case the database was only briefly busy.")
		b.AskPerson("Then tell the person the database cannot be reached and ask them to check that Postgres is running.")
		return guidance.DatabaseUnreachableMessage
	case guidance.ReasonTooManyConnections:
		b.RepeatCall(f.Tool, nil, 0, "Try the same call once more: a connection may have closed since.")
		b.AskPerson(guidance.TooManyConnectionsAsk)
		return guidance.TooManyConnectionsMessage(sc.core.Commands)
	case guidance.ReasonCredentialRejected, guidance.ReasonGuardMissing, guidance.ReasonGuardOutdated:
		var bf *guidance.GuardBelowFloorError
		if te.Reason == guidance.ReasonGuardOutdated && errors.As(f.Err, &bf) {
			person, ls := guidance.GuardBelowFloorSteps(b, sc.core.Commands, guardmodel.RemoveOldInstallDoc)
			te.Links = ls
			return person
		}
		return guidance.FixSteps(b, sc.core.Commands, te.Reason)
	case guidance.ReasonEngineUnreachable:
		return guidance.EngineUnreachableSteps(b, sc.core.Commands, f.Tool)
	case guidance.ReasonSetupPending, guidance.ReasonSetupExpired:
		return sc.setupSteps(b, te, f)
	case guidance.ReasonDatabaseNotConfirmed:
		var dn *guidance.DatabaseNotConfirmedError
		if !errors.As(f.Err, &dn) {
			b.Fail(errors.New("a database waiting for confirmation needs its setup and address"))
			return ""
		}
		return handoff.ConfirmDatabaseSteps(b, dn.SetupID, dn.Database)
	case guidance.ReasonPagesOff:
		b.CallTool(guidance.ToolListPending, map[string]any{}, "Read the held writes: each has the link the person opens, since this engine serves no pages.")
		return ""
	}
	b.Fail(fmt.Errorf("UNAVAILABLE has no reason %q", te.Reason))
	return ""
}

// setupSteps: a pending setup is run by the person on their own computer;
// an expired one is renewed on the engine's machine (an OPERATOR step).
func (sc *Service) setupSteps(b *guidance.Steps, te *toolresult.ToolError, f guidance.Failure) string {
	if te.Reason == guidance.ReasonSetupExpired {
		return guidance.SetupExpiredSteps(b, sc.core.Commands)
	}
	var se *guidance.SetupError
	if !errors.As(f.Err, &se) {
		b.Fail(errors.New("a pending setup needs its code"))
		return ""
	}
	if se.ConnectOnly {
		b.CallTool(guidance.ToolStatus, map[string]any{}, "Call status: its setup problem says what the person or you do next.")
		return ""
	}
	person, ls := guidance.SetupPendingSteps(b, sc.core.Commands, se.Code, se.Fingerprint, true, sc.deps.ConnectBudget)
	te.Links = ls
	return person
}
