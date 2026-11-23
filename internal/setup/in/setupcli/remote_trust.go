package setupcli

import (
	"crypto/x509"
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

// pinOf is the engine's pin for host in the config's trust.d: its
// pin-<host> profile, or nil, read through h.
func pinOf(h Host, configPath, host string) *trustprofile.Profile {
	p := h.TrustProfileFor(configPath, host)
	if p == nil || !p.Exact() || p.Name != trustprofile.PinName(host) {
		return nil
	}
	return p
}

// pinnedSHA is the SHA-256 (DER, lowercase hex) of the certificate the
// engine has pinned for the target's host: the code's trustPin, "" when it
// has no pin.
func (r *remoteInit) pinnedSHA() string {
	p := pinOf(r.setup, r.f.ConfigPath, trustprofile.NormalizeHost(r.target.Host))
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
	p := pinOf(r.setup, r.f.ConfigPath, host)
	if p == nil {
		return false
	}
	chain, ferr := r.c.FetchChain(r.c.Ctx, host, int(cfg.Port))
	if ferr != nil || len(chain) == 0 {
		return false
	}
	return !pinned(p.Certificates(), chain[len(chain)-1])
}

// pinned reports whether top is one of the pinned certificates.
func pinned(certs []*x509.Certificate, top *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(top) {
			return true
		}
	}
	return false
}

// certificatePlan is the code for a changed certificate (CONTRACT.md,
// basalt init --remote, step 3): a code that changes no grant, no password
// and no policy, carrying engine. Never a new password: the credential is
// not refused, its server's certificate is. An UPGRADE code from guard
// version 0: it names no agent, so the role keeps its password and its
// grants, and its migrations are the ones the database lacks, none when it
// has them.
func (r *remoteInit) certificatePlan() (setup.Plan, error) {
	return setup.Plan{Kind: setupcode.KindUpgrade}, nil
}
