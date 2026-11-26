// Package crashfile finds a crash report's file for status
// (status.Deps.CrashFile).
package crashfile

import (
	"os"
	"path/filepath"
)

// Find is the file of report id in the first of dirs that has one, "" when
// none does.
func Find(dirs []string, id string) string {
	for _, d := range dirs {
		if p := filepath.Join(d, id+".json"); exists(p) {
			return p
		}
	}
	return ""
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
