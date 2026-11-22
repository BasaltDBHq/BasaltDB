package localsetup

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The database certificate of an install of a real database (CONTRACT.md,
// The install of a real database, The database certificate).

const (
	// CodeTrustRootMismatch: the trustRoot the page sent is not what the
	// database presents.
	CodeTrustRootMismatch = "TRUST_ROOT_MISMATCH"

	paramSSLMode  = "sslmode"
	sslVerifyFull = "verify-full"
)

// pin is a certificate authority the person trusted that this engine's own
// reading of the chain confirmed, held until the run writes it.
type pin struct {
	host    string
	port    int
	sha256  string
	top     *x509.Certificate
	caOnly  bool
	profile *trustprofile.Profile
}

// pinnedDial opens the admin connection with the pin's certificate as the
// only root for its host (pgdial.ConnConfigTrusting).
func pinnedDial(ctx context.Context, dsn string, p *trustprofile.Profile) (*pgx.Conn, error) {
	cfg, err := pgdial.ConnConfigTrusting(dsn, pgdial.Trust().Replacing(p.Name, p))
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

// probe reads the chain host:port presents with the TLS handshake alone.
func probe(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, nil, host, port)
}

func notVerified() *RefusalError {
	return refuse(CodeCertificateNotVerified, "The database's TLS certificate could not be verified for its host name.")
}

// connectError is the fixed refusal of a failed connection.
func connectError(ctx context.Context, err error) *RefusalError {
	var pg *pgconn.PgError
	switch {
	case pgdial.CertificateNotVerified(err):
		return notVerified()
	case errors.As(err, &pg) && len(pg.Code) >= 2 && pg.Code[:2] == "28":
		return refuse(CodeLoginFailed, "The database refused the login. Check the admin user and password.")
	case ctx.Err() != nil:
		return refuse(CodeTimeLimit, "The setup ran out of time; nothing changed.")
	}
	return refuse(CodeDatabaseUnreachable, "The database could not be reached. Check the host and port in the admin connection string.")
}

// connectAdmin opens the admin connection of a real install. A certificate
// that does not verify is offered to the person to trust when it can be
// pinned (an unknown authority, never a public one and never for a host a
// trust profile covers); with the person's trustRoot, the engine reads the
// chain itself and logs in only against that one certificate. The pin is nil
// when the certificate verified without one.
func (s *Service) connectAdmin(ctx context.Context, req Request) (*pgx.Conn, *pin, error) {
	conn, err := s.opts.Dial(ctx, req.DatabaseURL)
	if err == nil {
		return conn, nil, nil
	}
	if !pgdial.CertificateNotVerified(err) {
		return nil, nil, connectError(ctx, err)
	}
	p, err := s.readPin(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	conn, err = s.opts.DialPinned(ctx, req.DatabaseURL, p.profile)
	if err != nil {
		return nil, nil, connectError(ctx, err)
	}
	return conn, p, nil
}

// readPin reads the chain of the admin string's one host and makes the pin
// the person's trustRoot names, or the refusal that offers it.
func (s *Service) readPin(ctx context.Context, req Request) (*pin, error) {
	cfg, err := pgconn.ParseConfig(req.DatabaseURL)
	// A pin is for one host: a string that names several has none. (The
	// config's Fallbacks are the sslmode's, not other hosts.)
	if u, perr := url.Parse(req.DatabaseURL); err != nil || perr != nil || cfg.Host == "" || strings.Contains(u.Host, ",") {
		return nil, notVerified()
	}
	host := strings.ToLower(cfg.Host)
	if pgdial.Trust().For(host) != nil {
		return nil, notVerified() // a trust profile decides for this host
	}
	chain, err := s.opts.Probe(ctx, host, int(cfg.Port))
	if err != nil {
		return nil, notVerified()
	}
	now := s.opts.Now()
	seen := trustpin.Check(chain, host, now)
	if seen.Public || !seen.Pinnable() {
		return nil, notVerified()
	}
	if req.TrustRoot == "" {
		r := notVerified()
		r.TrustRoot = &TrustRoot{Subject: seen.Subject(), SHA256: seen.SHA256, ExpiresAt: seen.Top.NotAfter.UTC().Format(time.RFC3339)}
		return nil, r
	}
	_, prof, err := trustpin.Approved(chain, host, now, req.TrustRoot)
	switch {
	case errors.Is(err, trustpin.ErrPublic):
		return nil, notVerified()
	case err != nil:
		return nil, refuse(CodeTrustRootMismatch, "The database presents another certificate authority than the one you trusted. Nothing changed; check the setup again.")
	}
	return &pin{host: host, port: int(cfg.Port), sha256: seen.SHA256, top: seen.Top, caOnly: !seen.Full, profile: prof}, nil
}

// write records the pin in the ledger, in the run's transaction, and writes
// it to trust.d next to engine.json. A profile that covers the host by now
// refuses, unless it is this pin.
func (p *pin) write(ctx context.Context, tx pgx.Tx, configPath string) error {
	if err := guard.RecordTrustPin(ctx, tx, p.host, p.port, p.sha256); err != nil {
		return setupFailed()
	}
	if _, err := trustdir.PinNew(configPath, p.host, p.top, p.caOnly); err != nil {
		return setupFailed()
	}
	return nil
}

// withVerifyFull is dsn with sslmode=verify-full, so the pin applies to the
// agent's connection: a profile applies with verify-full only.
func withVerifyFull(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Set(paramSSLMode, sslVerifyFull)
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return u.String()
}
