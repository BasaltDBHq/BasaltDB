package status

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// CrashDirs are the directories status.crash reads, so a panic of the engine process itself (saved
// under the default state directory or the person's config directory) shows
// as well as a tool call's (under stateDir).
func CrashDirs(stateDir string) []string {
	dirs := []string{filepath.Join(stateDir, servicespec.CrashDirName)}
	if base, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(base, "basalt", servicespec.CrashDirName), filepath.Join(base, "basalt", "state", servicespec.CrashDirName))
	}
	dirs = append(dirs, filepath.Join(config.DefaultStateDir(runtime.GOOS), servicespec.CrashDirName))
	return slices.Compact(dirs)
}
