package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	statussvc "github.com/basaltdbhq/basaltdb/internal/status"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
)

func extraStatus(t *testing.T, edit func(*Deps)) (guidance.StatusReport, string) {
	t.Helper()
	d := deps()
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	edit(&d)
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	tool, _ := mcpcontract.Find(mcpcontract.MustLoad(), guidance.ToolStatus)
	return r, requireStatusSchema(t, tool, r)
}

func TestStatusShowsTheSavedCrashReportAndItsLink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rec := crash.Recorder{Dir: dir, Version: "v1.2.3", Scrub: crash.NewScrubber("", "", nil), Now: func() time.Time { return statusNow }}
	_, err := rec.Save(servicespec.CrashInput{Command: "query", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "x", Stack: []byte(strings.Repeat("main.f()\n\t/src/a.go:1 +0x1\n", 400))})
	require.NoError(t, err)
	newest, err := rec.Save(servicespec.CrashInput{Command: "write", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "x", Stack: []byte("main.g()\n\t/src/b.go:2 +0x2\n")})
	require.NoError(t, err)

	r, _ := extraStatus(t, func(d *Deps) { d.Status.CrashDirs = []string{dir} })
	require.NotNil(t, r.Crash)
	require.Equal(t, newest.ID, r.Crash.ID, "the newest report")
	require.Equal(t, "write", r.Crash.Command)
	require.Equal(t, filepath.Join(dir, newest.ID+".json"), r.Crash.Path)
	require.FileExists(t, r.Crash.Path)
	require.True(t, strings.HasPrefix(r.Crash.IssueURL, crash.IssueBase+"?"))
	require.LessOrEqual(t, len(r.Crash.IssueURL), 1800, "inside the link budget")
	require.True(t, r.Ready, "a saved report is not a problem")
}

func TestStatusCrashLinkIsCutToTheLinkBudget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rec := crash.Recorder{Dir: dir, Version: "v1", Scrub: crash.NewScrubber("", "", nil), Now: func() time.Time { return statusNow }}
	_, err := rec.Save(servicespec.CrashInput{Command: "query", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "x", Stack: []byte(strings.Repeat("main.f()\n\t/src/a.go:1 +0x1\n", 400))})
	require.NoError(t, err)
	r, _ := extraStatus(t, func(d *Deps) { d.Status.CrashDirs = []string{dir} })
	require.NotNil(t, r.Crash)
	require.LessOrEqual(t, len(r.Crash.IssueURL), 1800)
}

func TestStatusLeavesCrashOutWhenNoneIsSaved(t *testing.T) {
	t.Parallel()
	r, raw := extraStatus(t, func(d *Deps) { d.Status.CrashDirs = []string{filepath.Join(t.TempDir(), "none")} })
	require.Nil(t, r.Crash)
	require.NotContains(t, raw, `"crash"`)
	require.NoError(t, os.MkdirAll(t.TempDir(), 0o700))
}

func TestStatusShowsTheTablesTheAgentCanReadAndWrite(t *testing.T) {
	t.Parallel()
	r, _ := extraStatus(t, func(d *Deps) {
		d.Status.Access = func(context.Context) (statussvc.CatalogAccess, error) {
			return statussvc.CatalogAccess{Read: []string{"public.a", "public.b"}, Write: []string{"public.a"}, NotGranted: []string{"public.secret"}}, nil
		}
	})
	require.Equal(t, &guidance.AccessStatus{Read: []string{"public.a", "public.b"}, Write: []string{"public.a"}}, r.Access)
}

func TestStatusLeavesAccessOutWhenItCannotBeRead(t *testing.T) {
	t.Parallel()
	r, _ := extraStatus(t, func(d *Deps) {
		d.Status.Access = func(context.Context) (statussvc.CatalogAccess, error) {
			return statussvc.CatalogAccess{}, errors.New("down")
		}
	})
	require.Nil(t, r.Access)
	require.True(t, r.Ready, "an unreadable list is not a problem")
}

func TestStatusShowsPluginHealth(t *testing.T) {
	t.Parallel()
	want := []guidance.PluginHealth{
		{Name: "acme-ner", Instance: "client_x", Health: "NOT_READY", Problem: "PLUGIN_UNAVAILABLE"},
		{Name: "acme-ner", Instance: "default", Health: "READY"},
	}
	r, _ := extraStatus(t, func(d *Deps) {
		d.Status.Plugins = fakePlugins{health: map[string][]guidance.PluginHealth{"bot": want}}
	})
	require.Equal(t, want, r.Plugins)
}

func TestStatusLeavesPluginsOutWithoutEntries(t *testing.T) {
	t.Parallel()
	r, raw := extraStatus(t, func(d *Deps) { d.Status.Plugins = fakePlugins{} })
	require.Nil(t, r.Plugins)
	require.NotContains(t, raw, `"plugins"`)
}

func TestStatusLeavesTheCrashLinkOutWhenItCannotFitTheBudget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rec := crash.Recorder{Dir: dir, Version: strings.Repeat("v", 64), Scrub: crash.NewScrubber("", "", nil), Now: func() time.Time { return statusNow }}
	rep, err := rec.Save(servicespec.CrashInput{Command: strings.Repeat("c", 40), Kind: servicespec.CrashKindPanic, ErrorCode: strings.Repeat("E", 60), Value: "x", Stack: []byte(strings.Repeat("main.f()\n\t/src/a.go:1 +0x1\n", 400))})
	require.NoError(t, err)
	r, raw := extraStatus(t, func(d *Deps) { d.Status.CrashDirs = []string{dir}; d.Core.LinkBudget = 600 })
	require.NotNil(t, r.Crash)
	require.Equal(t, rep.ID, r.Crash.ID)
	require.Empty(t, r.Crash.IssueURL, "no link rather than one over the budget")
	require.NotContains(t, raw, "issueUrl")
	require.FileExists(t, r.Crash.Path, "the path is still given")
}
