package pii

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// maxLoggedNames bounds the column names one log line lists.
const maxLoggedNames = 50

// TickTimeout bounds the hourly check, so a database that does not answer
// (or a pool that has no free connection) cannot hold it for good.
const TickTimeout = time.Minute

// Watch is one agent's hourly classification check, run by its upkeep tick
// (and so also at start): it reloads the map when the fingerprint or the
// catalog moved, and logs the fields the store reports unclassified.
type Watch struct {
	agent   string
	classes *Map
	store   Classes
	log     *slog.Logger
}

// NewWatch returns the check for agent's map on store. It panics on a
// missing dependency.
func NewWatch(agent string, classes *Map, store Classes, log *slog.Logger) *Watch {
	if agent == "" || classes == nil || store == nil || log == nil {
		panic("piidict: agent, classes, store and logger required")
	}
	return &Watch{agent: agent, classes: classes, store: store, log: log}
}

// Tick reloads the map when needed and warns about unclassified columns
// and columns whose type changed. Names are not PII; no value is read.
func (w *Watch) Tick(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, TickTimeout)
	defer cancel()
	var errs []error
	reloaded, err := w.classes.Tick(ctx, w.store)
	switch {
	case err != nil:
		errs = append(errs, err)
	case reloaded:
		w.log.Info("pii: classification loaded", "agent", w.agent)
	}
	cols, err := w.store.Unclassified(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("pii_unclassified: %w", err))...)
	}
	var unclassified, changed []string
	for _, c := range cols {
		if !c.Changed {
			unclassified = append(unclassified, c.Name)
			continue
		}
		changed = append(changed, c.Name)
	}
	if len(unclassified) > 0 {
		w.log.Warn(fmt.Sprintf("pii: %d columns unclassified: %s", len(unclassified), nameList(unclassified)),
			"agent", w.agent, "fix", "run basalt init to label them")
	}
	if len(changed) > 0 {
		w.log.Warn(fmt.Sprintf("pii: %d columns changed type since they were labeled: %s", len(changed), nameList(changed)),
			"agent", w.agent, "fix", "run basalt init to review them")
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
