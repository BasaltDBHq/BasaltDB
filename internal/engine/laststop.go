package engine

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// PrivateDirMode is the mode of the folders the engine and its supervisor
// make for themselves.
const PrivateDirMode = 0o700

// ResolveSuperviseBinary looks up startedFrom again on m; a missing file is
// BinaryGoneError.
func ResolveSuperviseBinary(m Machine, startedFrom string) (string, error) {
	if err := m.StatPath(startedFrom); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", &BinaryGoneError{Path: startedFrom}
		}
		return "", err
	}
	return startedFrom, nil
}

// WriteLastStop records in stateDir why the supervisor gave up, at at.
func WriteLastStop(h Host, t Terminal, stateDir, reason, configPath string, at time.Time, log *slog.Logger) {
	raw, err := json.Marshal(servicespec.LastStopFileRecord{Reason: reason, At: at.UTC(), EngineSHA256: h.LastStopHashEngineJSON(configPath)})
	if err == nil {
		err = t.MakeDirs(stateDir, PrivateDirMode)
	}
	if err == nil {
		err = t.WriteFileAtomic(filepath.Join(stateDir, LastStopFile), raw)
	}
	if err != nil {
		log.Warn("could not record why the engine stopped", "err", err)
	}
}

// ClearLastStop removes the record of a give-up from stateDir on m.
func ClearLastStop(m Machine, stateDir string, log *slog.Logger) {
	if err := m.RemoveFile(filepath.Join(stateDir, LastStopFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warn("could not remove the record of why the engine stopped", "err", err)
	}
}

// AnotherEngineRuns is true when the engine lock is held at every one of a
// few looks. A real engine holds it all the time; a probe by someone else
// (basalt status, a starting basalt mcp) holds it for a moment and reads as
// a holder, so one look that finds it free means no engine runs.
func AnotherEngineRuns(t Terminal, lockPath string) bool {
	return t.HeldAtEveryLook(func() bool { return t.LockHolderRuns(lockPath) }, time.Sleep)
}

// BinaryWatch finds the binary this process was started from.
type BinaryWatch interface {
	// ExecPath is the path this process was started from as arg0 names it,
	// looked up on PATH, and checked to be the running binary exe.
	ExecPath(arg0, exe string) (string, error)
}

// SuperviseBinaryPath is the path the supervisor was started from: a
// crash restart resolves it again, so a new file at the same path is run
// and a missing one is not looped on.
func SuperviseBinaryPath(b BinaryWatch) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return b.ExecPath(os.Args[0], exe)
}
