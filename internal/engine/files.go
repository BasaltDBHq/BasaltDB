package engine

import "path/filepath"

const lockFileName = "engine.lock"

// LockPath is the engine's lock file in socket directory dir: held while
// the engine runs, with its pid (basalt status reads both).
func LockPath(dir string) string { return filepath.Join(dir, lockFileName) }

// LastStopFile is the supervisor's record of giving up, in the state
// directory (basalt engine --supervise).
const LastStopFile = "last-stop.json"

// StartedByOrHand is why an engine started, v, or "hand" when empty.
func StartedByOrHand(v string) string {
	if v == "" {
		return "hand"
	}
	return v
}
