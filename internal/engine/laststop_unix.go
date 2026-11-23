//go:build unix

package engine

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// maxLastStopBytes bounds what is read of last-stop.json; maxReasonRunes what
// is shown.
const (
	maxLastStopBytes = 4096
	maxReasonRunes   = 300
)

// ReadLastStop reads why the supervisor gave up, from dir (the state
// directory): ok is false when there is no usable record. It is read as
// text and shown, never trusted for anything else.
func ReadLastStop(dir string) (guidance.LastStop, bool) {
	// Not a symlink, and never blocking on a pipe someone left there.
	f, err := os.OpenFile(filepath.Join(dir, LastStopFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return guidance.LastStop{}, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return guidance.LastStop{}, false
	}
	var rec lastStopJSON
	if err := json.NewDecoder(io.LimitReader(f, maxLastStopBytes)).Decode(&rec); err != nil || rec.Reason == "" {
		return guidance.LastStop{}, false
	}
	if r := []rune(rec.Reason); len(r) > maxReasonRunes {
		rec.Reason = string(r[:maxReasonRunes])
	}
	rec.Reason = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, rec.Reason)
	return guidance.LastStop{Reason: rec.Reason, At: rec.At.UTC(), EngineSHA256: rec.EngineSHA256}, true
}

// lastStopJSON is last-stop.json: why the supervisor gave up, when, and the
// SHA-256 of engine.json at that moment.
type lastStopJSON struct {
	Reason       string    `json:"reason"`
	At           time.Time `json:"at"`
	EngineSHA256 string    `json:"engineSha256,omitempty"`
}
