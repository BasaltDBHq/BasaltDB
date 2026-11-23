package status

import (
	"context"
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// LogGuard logs the agent's guard as the engine starts serving it. It runs
// beside the serving, never before it, so the sockets are bound whatever
// the database does (CONTRACT.md, Next steps). A guard
// that is missing or misses a breaking migration, or a database the engine
// cannot reach, does not stop the engine: the agent gets status and its
// problems, and the guard is read again on each call.
func LogGuard(ctx context.Context, probe Probe, log *slog.Logger) {
	st, err := probe.GuardStatus(ctx)
	switch {
	case err != nil:
		log.Error("cannot read the guard; only status works until the database answers", "err", err)
	case !st.Served():
		log.Error("the guard cannot serve this agent; only status works until it is installed or upgraded",
			"guard", st.State, "installed", st.Installed, "build", st.Build, "missingBreaking", st.MissingBreaking)
	case st.State == guardmodel.GuardUpgradeAvailable:
		log.Warn("the guard misses non-breaking migrations; the guard update basalt init links to adds them", "missingNonBreaking", st.MissingNonBreaking)
	}
}
