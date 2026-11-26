//go:build unix

package engineos

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// maxLastStopBytes bounds what is read of it; maxReasonRunes what is shown.
const (
	maxLastStopBytes = 4096
	maxReasonRunes   = 300
)

// ReadLastStop reads why the supervisor gave up, from the record at path
// (last-stop.json in the state directory): ok is false when there is no
// usable record. It is read as text and shown, never trusted for anything
// else.
func (OS) ReadLastStop(path string) (guidance.LastStop, bool) {
	// Not a symlink, and never blocking on a pipe someone left there.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return guidance.LastStop{}, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return guidance.LastStop{}, false
	}
	var rec servicespec.LastStopFileRecord
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
