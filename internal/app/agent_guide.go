package app

import (
	"log/slog"
	"time"

	statussvc "github.com/basaltdbhq/basaltdb/internal/status"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// newGuide is a Service with only what the error guidance reads, for an
// agent served without a database (a connect-only agent): its Failure
// renders that agent's errors. cmds are the commands as the agent's
// operator runs them.
func newGuide(name string, cmds guidance.Commands, log *slog.Logger, now func() time.Time, errs guidance.ErrorMap, connectBudget int) *Service {
	s := &Service{deps: Deps{
		Core:   coreDeps{Name: name, Commands: cmds, Log: log, Now: now, Errors: errs},
		Status: statussvc.Deps{ConnectBudget: connectBudget},
	}}
	s.wire()
	return s
}
