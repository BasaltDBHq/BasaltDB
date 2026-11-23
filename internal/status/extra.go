package status

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
// problem names it; nil when there is no reporter or no entry.
func (s statusDeps) pluginHealth() []guidance.PluginHealth {
	if s.plugins == nil {
		return nil
	}
	return s.plugins.PluginHealth(s.name)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
