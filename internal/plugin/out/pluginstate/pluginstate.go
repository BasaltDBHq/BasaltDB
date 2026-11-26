// Package pluginstate reads and writes the plugin host's state files in the
// engine's state directory: the outbound adapter behind
// plugin.Ports.WriteFeedCursor and plugin.Ports.ReadFeedCursor.
package pluginstate

import (
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

const (
	// dirMode keeps the engine's state to its own OS user.
	dirMode = 0o700
	// fileMode keeps a state file to the engine's own OS user.
	fileMode = 0o600
)

// WriteFeedCursor writes raw whole to name in dir, making dir first: a
// temporary file renamed into place, mode 0600.
func WriteFeedCursor(dir, name string, raw []byte) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	// A cursor lost in a crash replays events, which at least once allows:
	// no directory sync.
	return atomicfile.Write(filepath.Join(dir, name), raw, atomicfile.Options{Mode: fileMode})
}

// ReadFeedCursor reads the cursor file name in dir whole.
func ReadFeedCursor(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}
