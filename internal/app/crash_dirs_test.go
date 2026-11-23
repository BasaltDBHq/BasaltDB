package app

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
)

// A panic of the engine process itself on a laptop is saved under the
// person's config directory, not the engine's stateDir; status.crash must
// still find it.
func TestCrashDirsFindAnEngineProcessPanic(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	if runtime.GOOS == "darwin" {
		cfg = filepath.Join(cfg, "Library", "Application Support")
	}
	rec := crash.Recorder{Dir: filepath.Join(cfg, "basalt", crash.DirName), Version: "v1", Scrub: crash.NewScrubber("", "", nil), Now: time.Now}
	rep, err := rec.Save(crash.Input{Command: "engine", Kind: crash.KindPanic, ErrorCode: "INTERNAL", Value: "x", Stack: []byte("main.f()\n\t/src/a.go:1 +0x1\n")})
	require.NoError(t, err)

	got := crash.List(crashDirs(t.TempDir())...)
	require.Len(t, got, 1)
	require.Equal(t, rep.ID, got[0].ID)
}
