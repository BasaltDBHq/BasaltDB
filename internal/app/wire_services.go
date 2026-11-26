package app

import (
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// wireHandoff fills the ports the connect probe declares with the Postgres
// adapter's: the trust profiles the engine holds now, the login that
// trusts them, and the reader of a refused login's server message. A port
// the caller already set stays.
func wireHandoff(o handoffOptions) handoffOptions {
	if o.Prober.Trust == nil {
		o.Prober.Trust = pgdial.Trust
	}
	if o.Prober.Login == nil {
		o.Prober.Login = pgdial.Login
	}
	if o.Prober.Errors == nil {
		o.Prober.Errors = pgErrors{}
	}
	return o
}
