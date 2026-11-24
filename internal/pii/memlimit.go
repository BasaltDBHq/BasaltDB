package pii

import (
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// MemLimitFactor sizes GOMEMLIMIT from pii.maxMemoryMB: a dictionary build
// holds up to the budget in hashes, and the rest of the engine gets as much
// again. The mapped dictionary file is page cache, not heap.
const MemLimitFactor = 2

// EnvGoMemLimit is the Go runtime's own setting; when the operator set it,
// the engine keeps it.
const EnvGoMemLimit = "GOMEMLIMIT"

// SetMemoryLimit sets the Go heap's soft limit from the PII budget, unless
// GOMEMLIMIT is set in the environment.
func SetMemoryLimit(p config.PII, log *slog.Logger) {
	if os.Getenv(EnvGoMemLimit) != "" {
		log.Info("pii: keeping GOMEMLIMIT from the environment")
		return
	}
	limit := p.MaxMemoryBytes() * MemLimitFactor
	debug.SetMemoryLimit(limit)
	log.Info("pii: memory limit set", "goMemLimitBytes", limit, "maxMemoryMB", p.MaxMemoryMB)
}
