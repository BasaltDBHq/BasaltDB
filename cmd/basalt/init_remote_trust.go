package main

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The database certificate on persona 2 (CONTRACT.md, Pinning from the
// connect page): basalt init --remote never pins. The person trusts a
// certificate on the connect page, and the bot's engine pins it only after
// its own reading of the chain matches. These helpers stand alone, on
// pkg/trustpin and trustdir, so init --remote needs nothing of the removed
// basalt trust commands.

// noteUnknownAuthority says, before any login, that the credential's host
// presents a chain no authority here verifies and that no profile covers:
// the person trusts it on the connect page. Nothing is pinned. A chain that
// cannot be read, or that verifies, says nothing.
func (r *remoteInit) noteUnknownAuthority() {
	if r.base == nil || r.c.FetchChain == nil {
		return
	}
	cfg, err := pgconn.ParseConfig(r.base.String())
	if err != nil || cfg.Host == "" || cfg.TLSConfig == nil || cfg.TLSConfig.RootCAs != nil {
		return
	}
	host := trustprofile.NormalizeHost(cfg.Host)
	if r.setup.TrustProfileFor(r.f.ConfigPath, host) != nil {
		return // a profile, a pin included, decides; a changed pin shows at the login
	}
	chain, err := r.c.FetchChain(r.c.Ctx, host, int(cfg.Port))
	if err != nil {
		return
	}
	if seen := trustpin.Check(chain, host, r.c.Now()); seen.Pinnable() {
		fmt.Fprintf(r.c.Stderr, "basalt: %s presents a certificate authority no authority on this machine verifies: %s\n",
			cli.TerminalText(host), setup.ConnectPageTrust)
	}
}

// pinnedSHA is the SHA-256 (DER, lowercase hex) of the certificate the
// engine has pinned for the target's host: the code's trustPin, "" when it
// has no pin.
func (r *remoteInit) pinnedSHA() string {
	p := setup.PinOf(r.setup, r.f.ConfigPath, trustprofile.NormalizeHost(r.target.Host))
	if p == nil || len(p.Certificates()) == 0 {
		return ""
	}
	return trustprofile.DERSHA256(p.Certificates()[0])
}

// rootChanged reports whether err, a login of dsn, failed on the
// certificate of a host pinned in the config's trust.d whose chain top now
// (read with the TLS handshake alone) is not the pinned one:
// TRUST_ROOT_CHANGED. Never accepted here: the connect page asks the
// person, and the engine checks its own reading.
func (r *remoteInit) rootChanged(dsn string, err error) bool {
	if r.c.FetchChain == nil || !trustprofile.CertificateNotVerified(err) {
		return false
	}
	cfg, perr := pgconn.ParseConfig(dsn)
	if perr != nil || cfg.Host == "" {
		return false
	}
	host := trustprofile.NormalizeHost(cfg.Host)
	p := setup.PinOf(r.setup, r.f.ConfigPath, host)
	if p == nil {
		return false
	}
	chain, ferr := r.c.FetchChain(r.c.Ctx, host, int(cfg.Port))
	if ferr != nil || len(chain) == 0 {
		return false
	}
	return !setup.Pinned(p.Certificates(), chain[len(chain)-1])
}

func (r *remoteInit) certificatePlan() (setup.Plan, error) {
	return setup.Plan{Kind: setupcode.KindUpgrade}, nil
}
