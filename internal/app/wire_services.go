package app

import (
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/handoffnet"
	"github.com/basaltdbhq/basaltdb/internal/lib/sysdns"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
)

// wireHandoff fills the ports the connect probe declares with the Postgres
// adapter's: the trust profiles the engine holds now, the login that
// trusts them, and the reader of a refused login's server message; and
// with the network's: the system's DNS and the chain read. A port the
// caller already set stays.
func wireHandoff(o handoffOptions) handoffOptions {
	if o.Prober.Resolver == nil {
		o.Prober.Resolver = sysdns.Resolver{}
	}
	if o.Prober.ReadChain == nil {
		o.Prober.ReadChain = handoffnet.ReadChain
	}
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
