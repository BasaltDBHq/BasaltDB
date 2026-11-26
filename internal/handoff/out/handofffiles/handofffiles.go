// Package handofffiles is the address hand-off's reach into an agent's
// files (handoff.Files, handoff.RepinFiles, handoff.FinishFiles and
// handoff.CacheFile): its credential file, .pending, .secret and .lock, its
// entry in engine.json, the pins of trust.d, and the probe cache in the
// engine's state directory.
package handofffiles

// The agent's files next to its credential file: the same names as
// handoff.PendingSuffix and handoff.LockSuffix.
const (
	pendingSuffix = ".pending"
	lockSuffix    = ".lock"
)
