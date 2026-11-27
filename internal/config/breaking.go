package config

import (
	"encoding/json"
	"errors"
	"fmt"
)

// BreakingEpoch is the breaking epoch of the engine.json this build writes
// and reads (CONTRACT.md, Engine config, breaking). A breaking release, one
// whose engine.json or engine service no older one can be updated to,
// bumps it by one: basalt init then moves an engine.json below it aside
// and sets the computer up again (the install and restart scripts'
// reset), as the setup page replaces a guard below the update floor.
// A release that raises the guard's update floor (a migration marked
// reinstall) bumps it too: only an engine with no config runs the setup
// page's INSTALL, which is what replaces such a guard.
const BreakingEpoch = 1

// EpochOf is the breaking epoch of an engine.json: its "breaking" number;
// else 0 for the shape of the releases before the first breaking one (a
// top-level "directAddr", or an agent with its own "credentialFile" and
// no "store"); else 1, today's shape written before the field. The
// install and restart scripts read the same keys (osservice's
// config_epoch), and one set of test configs pins both. A file that is not
// a JSON object, or a "breaking" that is not a number, is left to the
// decoder: BreakingEpoch.
func EpochOf(raw []byte) int {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return BreakingEpoch
	}
	if b, ok := top["breaking"]; ok {
		var n int
		if err := json.Unmarshal(b, &n); err != nil {
			return BreakingEpoch
		}
		return n
	}
	if _, ok := top["directAddr"]; ok {
		return 0
	}
	var agents []map[string]json.RawMessage
	if err := json.Unmarshal(top["agents"], &agents); err != nil {
		return 1
	}
	for _, a := range agents {
		_, cred := a["credentialFile"]
		_, store := a["store"]
		if cred && !store {
			return 0
		}
	}
	return 1
}

// BreakingError is the error of an engine.json of another breaking epoch
// than this build's: Load and every command refuse it.
type BreakingError struct{ Epoch int }

func (e *BreakingError) Error() string {
	if e.Epoch > BreakingEpoch {
		return fmt.Sprintf("it was written by a newer BasaltDB (breaking %d, this basalt reads %d): update basalt, then run basalt init again", e.Epoch, BreakingEpoch)
	}
	return fmt.Sprintf("it was written by a BasaltDB release before the last breaking one (breaking %d, this basalt needs %d): run basalt init, which moves it aside and sets this computer up again", e.Epoch, BreakingEpoch)
}

// IsBreaking reports whether err (from Load) is that refusal, so a caller
// that otherwise ignores a config it cannot read can still show it.
func IsBreaking(err error) bool {
	var e *BreakingError
	return errors.As(err, &e)
}

// refuseBreaking refuses an engine.json of another breaking epoch.
func refuseBreaking(raw []byte) error {
	if e := EpochOf(raw); e != BreakingEpoch {
		return &BreakingError{Epoch: e}
	}
	return nil
}
