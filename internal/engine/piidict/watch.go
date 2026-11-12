package piidict

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// maxLoggedNames bounds the column names one log line lists.
const maxLoggedNames = 50

// Watch is one agent's hourly classification check, run by its upkeep tick
// (and so also at start): it reloads the map when the fingerprint or the
// catalog moved, and logs the columns pii_unclassified() reports.
type Watch struct {
	agent   string
	classes *Map
	db      guard.Querier
	log     *slog.Logger
}

// NewWatch returns the check for agent's map on db. It panics on a missing
// dependency.
func NewWatch(agent string, classes *Map, db guard.Querier, log *slog.Logger) *Watch {
	if agent == "" || classes == nil || db == nil || log == nil {
		panic("piidict: agent, classes, db and logger required")
	}
	return &Watch{agent: agent, classes: classes, db: db, log: log}
}

// Tick reloads the map when needed and warns about unclassified columns
// and columns whose type changed. Names are not PII; no value is read.
func (w *Watch) Tick(ctx context.Context) error {
	var errs []error
	reloaded, err := w.classes.Tick(ctx, w.db)
	switch {
	case err != nil:
		errs = append(errs, err)
	case reloaded:
		w.log.Info("pii: classification loaded", "agent", w.agent)
	}
	cols, err := guard.PIIUnclassified(ctx, w.db)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("pii_unclassified: %w", err))...)
	}
	var unclassified, changed []string
	for _, c := range cols {
		if c.Unclassified() {
			unclassified = append(unclassified, c.Name())
			continue
		}
		changed = append(changed, c.Name())
	}
	if len(unclassified) > 0 {
		w.log.Warn(fmt.Sprintf("pii: %d columns unclassified: %s", len(unclassified), nameList(unclassified)),
			"agent", w.agent, "fix", "run basalt classify")
	}
	if len(changed) > 0 {
		w.log.Warn(fmt.Sprintf("pii: %d columns changed type since basalt classify: %s", len(changed), nameList(changed)),
			"agent", w.agent, "fix", "run basalt classify to review them")
	}
	return errors.Join(errs...)
}

// nameList joins at most maxLoggedNames names, then "…".
func nameList(names []string) string {
	if len(names) <= maxLoggedNames {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:maxLoggedNames], ", ") + ", …"
}
