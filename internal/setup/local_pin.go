package setup

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The database certificate of an install of a real database (CONTRACT.md,
// The install of a real database, The database certificate).

const (
	// CodeTrustRootMismatch: the trustRoot the page sent is not what the
	// database presents.
	CodeTrustRootMismatch = "TRUST_ROOT_MISMATCH"

	defaultPort = 5432
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

// loginRefused: the database refused the login (SQLSTATE class 28,
// invalid authorization).
func loginRefused(err error) bool {
	code := SQLStateOf(err)
	return len(code) >= 2 && code[:2] == "28"
}

func notVerified() *RefusalError {
	return refuse(CodeCertificateNotVerified, "The database's TLS certificate could not be verified for its host name.")
}

// connectError is the fixed refusal of a failed connection.
func (s *LocalService) connectError(ctx context.Context, err error) *RefusalError {
	switch {
	case s.be.CertificateNotVerified(err):
		return notVerified()
	case loginRefused(err):
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
func (s *LocalService) connectAdmin(ctx context.Context, req Request) (Conn, *pin, error) {
	conn, err := s.opts.Dial(ctx, req.DatabaseURL)
	if err == nil {
		return conn, s.keptPin(req), nil
	}
	if !s.be.CertificateNotVerified(err) {
		return nil, nil, s.connectError(ctx, err)
	}
	p, err := s.readPin(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	conn, err = s.opts.DialPinned(ctx, pinDSN(req.DatabaseURL), p.profile)
	if err != nil {
		return nil, nil, s.connectError(ctx, err)
	}
	return conn, p, nil
}

// readPin reads the chain of the admin string's one host and makes the pin
// the person's trustRoot names, or the refusal that offers it.
func (s *LocalService) readPin(ctx context.Context, req Request) (*pin, error) {
	host, port, ok := hostPort(req.DatabaseURL)
	if !ok {
		return nil, notVerified()
	}
	if s.opts.Profiles().For(host) != nil {
		return nil, notVerified() // a trust profile decides for this host
	}
	chain, err := s.opts.Probe(ctx, host, port)
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
	return &pin{host: host, port: port, sha256: seen.SHA256, top: seen.Top, caOnly: !seen.Full, profile: prof}, nil
}

// write records the pin in the ledger, in the run's transaction, and writes
// it to trust.d next to engine.json. A profile that covers the host by now
// refuses, unless it is this pin.
func (s *LocalService) writePin(ctx context.Context, p *pin, tx Tx) error {
	if err := s.be.RecordTrustPin(ctx, tx.Port(), p.host, p.port, p.sha256); err != nil {
		return s.setupFailed("record the trust pin", err)
	}
	if _, err := s.be.PinFileNew(s.opts.ConfigPath, p.host, p.top, p.caOnly); err != nil {
		return s.setupFailed("write the trust pin", err)
	}
	return nil
}

// keptPin is the pin the person's trustRoot names when this engine's trust.d
// already holds it, so the connection verified without a new reading: a run
// that follows a failed commit, which rolled the ledger record back but left
// the pin. nil when there is no trustRoot or no such pin. The run records it
// again; writing it finds it there already.
func (s *LocalService) keptPin(req Request) *pin {
	if req.TrustRoot == "" {
		return nil
	}
	host, port, ok := hostPort(req.DatabaseURL)
	if !ok {
		return nil
	}
	prof := s.opts.Profiles().For(host)
	if prof == nil || prof.Name != trustprofile.PinName(host) {
		return nil
	}
	for _, c := range prof.Certificates() {
		if trustprofile.DERSHA256(c) == req.TrustRoot {
			return &pin{host: host, port: port, sha256: req.TrustRoot, top: c, caOnly: prof.VerifiesCA(), profile: prof}
		}
	}
	return nil
}

// hostPort is the one host and port a postgres:// string names, the host in
// lowercase; false for a string that names several hosts or none. It reads
// the URL alone: a string with an sslrootcert that does not exist must still
// be pinnable.
func hostPort(dsn string) (string, int, bool) {
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" || strings.Contains(u.Host, ",") {
		return "", 0, false
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return "", 0, false
		}
	}
	return strings.ToLower(u.Hostname()), port, true
}

// pinDSN is dsn as the pinned login and the agent's credential use it:
// sslmode=verify-full, so the pin applies (a profile applies with verify-full
// only), and no sslrootcert, which would name another root than the pin.
func pinDSN(dsn string) string { return withVerifyFull(dsn) }

// withVerifyFull is dsn with sslmode=verify-full and no sslrootcert.
func withVerifyFull(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Set(paramSSLMode, sslVerifyFull)
	q.Del("sslrootcert")
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return u.String()
}
