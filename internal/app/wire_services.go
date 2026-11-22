package app

import (
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
)

// wireHandoff fills the ports the connect probe declares with the Postgres
// adapter's: the trust profiles the engine holds now, and the connection
// config that trusts them. A port the caller already set stays.
func wireHandoff(o HandoffOptions) HandoffOptions {
	if o.Prober.Trust == nil {
		o.Prober.Trust = pgdial.Trust
	}
	if o.Prober.ConnConfig == nil {
		o.Prober.ConnConfig = pgdial.ConnConfigTrusting
	}
	return o
}
