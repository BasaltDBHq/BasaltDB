package pgdial

import (
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// trustConfig makes every TLS config of cfg that verifies the host name
// (sslmode=verify-full) for a host one of set's profiles matches trust that
// profile's roots as well as the system's authorities. Each host is matched
// on its own, so a multi-host connection string trusts each profile's roots
// only for that profile's hosts. A config that already has roots
// (sslrootcert, PGSSLROOTCERT, a service file or ~/.postgresql/root.crt)
// keeps them: the person named the root. The host name check stays on;
// verify-ca, require and weaker modes are left as pgx built them. Call it
// once per parsed config: on a copy for each new connection of a pool.
func trustConfig(cfg *pgconn.Config, set *trustprofile.Set) {
	trustprofile.TrustTLS(cfg.Host, cfg.TLSConfig, set)
	for _, fb := range cfg.Fallbacks {
		trustprofile.TrustTLS(fb.Host, fb.TLSConfig, set)
	}
}

// explainConfig is what verifies cfg's first host, a config parsed without
// trustConfig.
func explainConfig(cfg *pgconn.Config, set *trustprofile.Set) trustprofile.Applied {
	return trustprofile.ExplainTLS(cfg.Host, cfg.TLSConfig, set)
}
