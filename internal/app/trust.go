package app

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// TrustOf is status's TrustReporter for pool: what verifies its database's
// first host as the trust profiles stand when status asks (CONTRACT.md,
// Trust profiles), the chain top that host presents now (read with the TLS
// handshake alone, only for a pinned host whose certificate did not
// verify), and the pin the ledger records for it. It never writes a pin.
func TrustOf(pool *pgxpool.Pool) agent.TrustReporter {
	return func() agent.TrustReport {
		cfg := pool.Config().ConnConfig
		a, refused := pgdial.TrustOfConfig(&cfg.Config)
		host, port := trustprofile.NormalizeHost(cfg.Host), cfg.Port
		return agent.TrustReport{
			Applied: a, Refused: refused, Port: port,
			Presented: func(ctx context.Context) (*x509.Certificate, error) {
				chain, err := trustpin.Fetch(ctx, nil, host, int(port))
				if err != nil {
					return nil, err
				}
				if len(chain) == 0 {
					return nil, errors.New("no certificate")
				}
				return chain[len(chain)-1], nil
			},
			Recorded: func(ctx context.Context) (string, bool, error) {
				return guard.RecordedTrustPin(ctx, pool, host, int(port))
			},
		}
	}
}
