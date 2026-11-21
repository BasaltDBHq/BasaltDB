package engine

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// TrustOf is status's TrustReporter for pool: what verifies its database's
// first host as the trust profiles stand when status asks (CONTRACT.md,
// Trust profiles).
func TrustOf(pool *pgxpool.Pool) agent.TrustReporter {
	return func() agent.TrustReport {
		cfg := pool.Config().ConnConfig
		a, refused := pgdial.TrustOfConfig(&cfg.Config)
		return agent.TrustReport{Applied: a, Refused: refused}
	}
}
