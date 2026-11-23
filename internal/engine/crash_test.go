package engine_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
)

// saved is one SaveIn call a fakeRecorder took.
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

func (r fakeRecorder) SaveIn(dir string, shared bool, in servicespec.CrashInput) (string, error) {
	*r.calls = append(*r.calls, saved{dir, shared, in})
	if r.fail[dir] {
		return "", errors.New("disk full in " + dir)
	}
	return "r-1", nil
}

// fakeCrashHost has its per-user config directory at base.
type fakeCrashHost struct {
	rec  fakeRecorder
	base string
}

func (h fakeCrashHost) UserConfigDir() (string, error) { return h.base, nil }

func (h fakeCrashHost) NewRecorder() engine.Recorder { return h.rec }

func (fakeCrashHost) TerminalText(s string) string { return "<" + s + ">" }

func (fakeCrashHost) InfoOwnerUID(os.FileInfo) (int, bool) { return 0, false }

func (fakeCrashHost) LastStopHashEngineJSON(string) string { return "" }

func (fakeCrashHost) WriteFileAtomic(string, []byte) error { return nil }

func (fakeCrashHost) HeldAtEveryLook(func() bool, func(time.Duration)) bool { return false }

// crashDirsOf are the person's and the system's crash directories for a
// person whose config directory is base.
func crashDirsOf(base string) (user, state string) {
	return filepath.Join(base, config.UserDirName, servicespec.CrashDirName),
		filepath.Join(config.DefaultStateDir(runtime.GOOS), servicespec.CrashDirName)
}

func TestReportPanicNamesTheSavedReport(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	user, state := crashDirsOf(base)
	var calls []saved
	h := fakeCrashHost{rec: fakeRecorder{fail: map[string]bool{state: true}, calls: &calls}, base: base}
	var w bytes.Buffer
	engine.ReportPanic(h, h, &w, "engine", "boom", []byte("stack"))
	require.Equal(t, "basalt: crashed; report r-1 was saved in <"+user+">: the agent's status tool names it, with the link to file it on GitHub\n", w.String())
	require.Equal(t, []saved{
		{state, true, servicespec.CrashInput{Command: "engine", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "boom", Stack: []byte("stack")}},
		{user, false, servicespec.CrashInput{Command: "engine", Kind: servicespec.CrashKindPanic, ErrorCode: "INTERNAL", Value: "boom", Stack: []byte("stack")}},
	}, calls, "the engine tries its state directory first, and shares only that one")
}

func TestReportPanicSaysWhenNothingIsSaved(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	user, state := crashDirsOf(base)
	var calls []saved
	h := fakeCrashHost{rec: fakeRecorder{fail: map[string]bool{user: true, state: true}, calls: &calls}, base: base}
	var w bytes.Buffer
	engine.ReportPanic(h, h, &w, "init", "boom", nil)
	require.Equal(t, "basalt: crashed, and the crash report could not be saved (<disk full in "+state+">)\n", w.String())
	require.Equal(t, []string{user, state}, []string{calls[0].dir, calls[1].dir}, "a command other than the engine tries the person's directory first")
	require.False(t, calls[0].shared || calls[1].shared, "a command other than the engine shares no directory")
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
