package engine_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// saved is one Save call a fakeRecorder took.
type saved struct {
	dir    string
	shared bool
	in     servicespec.CrashInput
}

// fakeRecorder fails in the directories in fail and records every call.
type fakeRecorder struct {
	fail  map[string]bool
	calls *[]saved
}

func (r fakeRecorder) Save(dir string, shared bool, in servicespec.CrashInput) (string, error) {
	*r.calls = append(*r.calls, saved{dir, shared, in})
	if r.fail[dir] {
		return "", errors.New("disk full in " + dir)
	}
	return "r-1", nil
}

type fakeCrashHost struct {
	rec  fakeRecorder
	dirs []string
}

func (h fakeCrashHost) NewRecorder(string) (engine.Recorder, []string) { return h.rec, h.dirs }

func (fakeCrashHost) TerminalText(s string) string { return "<" + s + ">" }

func TestReportPanicNamesTheSavedReport(t *testing.T) {
	t.Parallel()
	var calls []saved
	h := fakeCrashHost{rec: fakeRecorder{fail: map[string]bool{"/state": true}, calls: &calls}, dirs: []string{"/state", "/user"}}
	var w bytes.Buffer
	engine.ReportPanic(h, h, &w, "engine", "boom", []byte("stack"))
	require.Equal(t, "basalt: crashed; report r-1 was saved in </user>: the agent's status tool names it, with the link to file it on GitHub\n", w.String())
	require.Equal(t, []saved{
		{"/state", true, servicespec.CrashInput{Command: "engine", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "boom", Stack: []byte("stack")}},
		{"/user", false, servicespec.CrashInput{Command: "engine", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "boom", Stack: []byte("stack")}},
	}, calls, "only the engine's first directory is shared")
}

func TestReportPanicSaysWhenNothingIsSaved(t *testing.T) {
	t.Parallel()
	var calls []saved
	h := fakeCrashHost{rec: fakeRecorder{fail: map[string]bool{"/user": true, "/state": true}, calls: &calls}, dirs: []string{"/user", "/state"}}
	var w bytes.Buffer
	engine.ReportPanic(h, h, &w, "init", "boom", nil)
	require.Equal(t, "basalt: crashed, and the crash report could not be saved (<disk full in /state>)\n", w.String())
	require.False(t, calls[0].shared, "a command other than the engine shares no directory")
}

type configDir struct {
	dir string
	err error
}

func (c configDir) UserConfigDir() (string, error) { return c.dir, c.err }

func TestUserCrashDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	require.Equal(t, filepath.Join(base, config.UserDirName, servicespec.CrashDirName), engine.UserCrashDir(configDir{dir: base}))
	require.Empty(t, engine.UserCrashDir(configDir{err: errors.New("no home")}))
}
