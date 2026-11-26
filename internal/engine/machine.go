package engine

import (
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// ReadLastStop reads why the supervisor gave up, from dir (the state
// directory): ok is false when there is no usable record. It is read as
// text and shown, never trusted for anything else.
func ReadLastStop(m Machine, dir string) (guidance.LastStop, bool) {
	return m.ReadLastStop(filepath.Join(dir, LastStopFile))
}

// LastStopReader is ReadLastStop on m.
func LastStopReader(m Machine) func(dir string) (guidance.LastStop, bool) {
	return func(dir string) (guidance.LastStop, bool) { return ReadLastStop(m, dir) }
}
