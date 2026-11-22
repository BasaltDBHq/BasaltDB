package engine

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// memLimitFactor sizes GOMEMLIMIT from pii.maxMemoryMB: a dictionary build
// holds up to the budget in hashes (piidict), and the rest of the engine
// gets as much again. The mapped dictionary file is page cache, not heap.
const memLimitFactor = 2

// envGoMemLimit is the Go runtime's own setting; when the operator set it,
// the engine keeps it.
const envGoMemLimit = "GOMEMLIMIT"

// openPII opens the engine's PII state in stateDir (M5.1 plan, section 5):
// k_master in pii.key, created on first start and refused when its mode is
// wider than 0600 (the engine does not start), and the dictionary in pii/.
// It sets GOMEMLIMIT from the budget and writes status.json.
func openPII(stateDir string, p config.PII, log *slog.Logger) (*pii.FuseDictionary, error) {
	if err := os.MkdirAll(stateDir, stateDirMode); err != nil {
		return nil, fmt.Errorf("pii: state directory %s: %w", stateDir, err)
	}
	keys, err := pii.LoadKeys(filepath.Join(stateDir, pii.KeyFileName), rand.Reader)
	if err != nil {
		return nil, err
	}
	opts := pii.DefaultDictionaryOptions()
	opts.MaxMemoryBytes = p.MaxMemoryBytes()
	dict, err := pii.OpenDictionary(stateDir, keys, opts)
	if err != nil {
		return nil, err
	}
	if why := dict.Discarded(); why != nil {
		log.Warn("pii: the saved dictionary was not usable; the first scan rebuilds it", "err", why)
	}
	if err := dict.WriteStatus(); err != nil {
		log.Warn("pii: could not write the dictionary status", "err", err)
	}
	setMemoryLimit(p, log)
	return dict, nil
}

// setMemoryLimit sets the Go heap's soft limit from the PII budget, unless
// GOMEMLIMIT is set in the environment.
func setMemoryLimit(p config.PII, log *slog.Logger) {
	if os.Getenv(envGoMemLimit) != "" {
		log.Info("pii: keeping GOMEMLIMIT from the environment")
		return
	}
	limit := p.MaxMemoryBytes() * memLimitFactor
	debug.SetMemoryLimit(limit)
	log.Info("pii: memory limit set", "goMemLimitBytes", limit, "maxMemoryMB", p.MaxMemoryMB)
}
