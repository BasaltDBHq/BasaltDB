package laststop

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// DefaultStartHoldOff is how long basalt mcp waits after a supervisor
// give-up before it starts another supervisor, counted from last-stop.json's
// at, never from the file's mtime.
const DefaultStartHoldOff = time.Minute

// LastStopFileRecord is last-stop.json: why the supervisor gave up, when,
// and the SHA-256 of engine.json at that moment.
type LastStopFileRecord struct {
	Reason       string    `json:"reason"`
	At           time.Time `json:"at"`
	EngineSHA256 string    `json:"engineSha256,omitempty"`
}

// HashEngineJSON is the lowercase hex SHA-256 of the file at path, or ""
// when the file cannot be read.
func HashEngineJSON(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// StartHoldOffUntil is when basalt mcp will next try a start from rec, or
// zero when the hold-off does not apply: the give-up is not in the past,
// the minute after at has passed, or engine.json has changed since the
// give-up (engineSha256 no longer matches the current file).
func StartHoldOffUntil(rec LastStopFileRecord, configPath string, now time.Time) (time.Time, bool) {
	if rec.Reason == "" || rec.At.IsZero() {
		return time.Time{}, false
	}
	at := rec.At.UTC()
	now = now.UTC()
	if now.Before(at) {
		return time.Time{}, false
	}
	until := at.Add(DefaultStartHoldOff)
	if !now.Before(until) {
		return time.Time{}, false
	}
	if rec.EngineSHA256 != "" {
		if got := HashEngineJSON(configPath); got != "" && got != rec.EngineSHA256 {
			return time.Time{}, false
		}
	}
	return until, true
}
