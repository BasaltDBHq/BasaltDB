package setupcli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// maxBreakingRead bounds the engine.json moveBreakingConfigAside reads, as
// config.Load bounds it.
const maxBreakingRead = 1 << 20

// maxOldFolders bounds the .old names moveBreakingConfigAside tries.
const maxOldFolders = 100

// moveBreakingConfigAside moves the folder of the engine.json at path to
// the first free <folder>.old, <folder>.old.2, ... when that engine.json
// was written before the last breaking release (config.EpochOf below
// config.BreakingEpoch), and returns where it went; "" when there is no
// such file or it is of this epoch. It never deletes, overwrites or nests
// a folder (CONTRACT.md, basalt init, A setup from before the last
// breaking release). basalt init runs it on a config in the person's own
// config folder, which no script running as root may name; the install
// and restart scripts do the same for the system path.
func moveBreakingConfigAside(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		// None, or one this user cannot read: nothing is moved, and the
		// command that loads it says what is wrong.
		return "", nil //nolint:nilerr // an unread config is never moved
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBreakingRead+1))
	_ = f.Close()
	if err != nil {
		return "", err
	}
	if len(raw) > maxBreakingRead || config.EpochOf(raw) >= config.BreakingEpoch {
		return "", nil // too large to be one: Load refuses it with its own words
	}
	dir := filepath.Dir(path)
	old := dir + ".old"
	for n := 2; ; n++ {
		if _, err := os.Lstat(old); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if n > maxOldFolders {
			return "", fmt.Errorf("%s was written by a BasaltDB release before the last breaking one, and %s.old to %s are all taken: delete the old ones, then run basalt init again", path, dir, old)
		}
		old = fmt.Sprintf("%s.old.%d", dir, n)
	}
	if err := os.Rename(dir, old); err != nil {
		return "", fmt.Errorf("%s was written by a BasaltDB release before the last breaking one, and its folder could not be moved aside: %w", path, err)
	}
	return old, nil
}

// breakingMovedLine is what basalt init says after moveBreakingConfigAside
// moved path's folder to old.
func breakingMovedLine(path, old string) string {
	return fmt.Sprintf("basalt: %s was written by a BasaltDB release before the last breaking one: its folder is moved to %s, and this computer is set up again. Delete that folder once the new setup works.", path, old)
}
