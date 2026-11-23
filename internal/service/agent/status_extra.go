package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// What status shows of what basalt crash, basalt access and basalt plugin
// check showed (CONTRACT.md, Crash reports; MCP tools, status).

// maxAccessTables bounds each of status.access's lists.
const maxAccessTables = 200

// Health values of a plugin entry in status.plugins, as the plugin's own
// health answer names them (basalt plugin check).
const (
	PluginHealthReady    = "READY"
	PluginHealthNotReady = "NOT_READY"
)

// PluginLister lists the plugin entries served to an agent. Optional on a
// PluginReporter: without it status.plugins is left out.
type PluginLister interface {
	PluginEntries(agent string) []PluginEntry
}

// PluginEntry is an enabled plugin entry that lists the agent.
type PluginEntry struct{ Name, Instance string }

// AccessReader lists the agent role's table privileges (session_user's).
type AccessReader func(ctx context.Context) (CatalogAccess, error)

// crashStatus is the newest report in the crash directory, or nil.
func (s statusDeps) crashStatus() *guidance.CrashStatus {
	if s.crashReports == nil || len(s.crashDirs) == 0 {
		return nil
	}
	reports := s.crashReports(s.crashDirs...)
	if len(reports) == 0 {
		return nil
	}
	rep := reports[0]
	link := rep.IssueURL(s.linkBudget)
	path := ""
	for _, d := range s.crashDirs {
		if p := filepath.Join(d, rep.ID+".json"); fileExists(p) {
			path = p
			break
		}
	}
	return &guidance.CrashStatus{
		ID: rep.ID, Time: rep.Time.UTC().Format("2006-01-02T15:04:05Z"), Version: rep.Version, Command: rep.Command,
		Path: path, IssueURL: link,
	}
}

// accessStatus is what the agent can read and write; nil when it cannot be
// read (the database is down) or no reader is set.
func (s statusDeps) accessStatus(ctx context.Context) *guidance.AccessStatus {
	if s.access == nil {
		return nil
	}
	a, err := s.access(ctx)
	if err != nil {
		return nil
	}
	out := &guidance.AccessStatus{Read: []string{}, Write: []string{}}
	out.Read, out.Truncated = clipTables(a.Read, out.Truncated)
	out.Write, out.Truncated = clipTables(a.Write, out.Truncated)
	return out
}

func clipTables(t []string, already bool) ([]string, bool) {
	if t == nil {
		return []string{}, already
	}
	if len(t) > maxAccessTables {
		return slices.Clone(t[:maxAccessTables]), true
	}
	return t, already
}

// pluginHealth lists the agent's plugin entries, each READY unless a plugin
// problem names it; nil when the reporter cannot list them.
func (s statusDeps) pluginHealth() []guidance.PluginHealth {
	l, ok := s.plugins.(PluginLister)
	if !ok {
		return nil
	}
	entries := l.PluginEntries(s.name)
	if len(entries) == 0 {
		return nil
	}
	probs := s.plugins.PluginProblems(s.name)
	out := make([]guidance.PluginHealth, 0, len(entries))
	for _, e := range entries {
		h := guidance.PluginHealth{Name: e.Name, Instance: e.Instance, Health: PluginHealthReady}
		for _, p := range probs {
			if p.Name == e.Name && p.Instance == e.Instance && p.Code != ProblemPluginNoticesDropped {
				h.Health, h.Problem = PluginHealthNotReady, p.Code
				break
			}
		}
		out = append(out, h)
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
