package handoff

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/supabaseca"
)

// The connection string settings the engine's agent credential uses for a
// collected address: a verified certificate always, channel binding when
// the probe showed it works (CONTRACT.md, The engine and a connect-only
// code, Yes).
const (
	paramSSLMode        = "sslmode"
	paramChannelBinding = "channel_binding"
	sslVerifyFull       = "verify-full"
	bindingRequire      = "require"
)

// SQLSTATEs a login bound to fail answers with.
const (
	// sqlstateInvalidPassword is a refused SCRAM exchange: with
	// channel_binding=require the client only gets this far over a TLS
	// connection whose certificate verified and a server that offered
	// SCRAM-SHA-256-PLUS.
	sqlstateInvalidPassword = "28P01"
	sqlstateClassAuth       = "28"
	// sqlstateInternal with supavisorNoTenant is Supabase's pooler not
	// knowing the user.
	sqlstateInternal  = "XX000"
	supavisorNoTenant = "Tenant or user not found"
)

// supabasePooler is the host suffix of Supabase's pooler (Supavisor), where
// the agent logs in as <role>.<ref>.
const supabasePooler = ".pooler.supabase.com"

// probeTimeout bounds one probe login.
const probeTimeout = 15 * time.Second

// probePasswordBytes is the size of the random password a probe sends.
const probePasswordBytes = 24

// ErrUnreachable is a probe that reached no server that verified: no
// address answered, or the certificate did not verify for the host name
// (problem DATABASE_UNREACHABLE_FROM_BOT). Every such failure is a
// *ReachError with its reason, which errors.Is matches to ErrUnreachable.
var ErrUnreachable = errors.New("the database cannot be reached from the bot's machine with a verified certificate")

// The results and reasons of a reach report (CONTRACT.md, Connect, The
// reach check).
const (
	ResultReachable   = "REACHABLE"
	ResultUnreachable = "UNREACHABLE"
	// ReasonAddressRefused: the host resolves to an address the engine
	// never connects to.
	ReasonAddressRefused = "ADDRESS_REFUSED"
	// ReasonNoRoute: no address of the server accepted a connection (a
	// host that does not resolve counts as this too).
	ReasonNoRoute = "NO_ROUTE"
	// ReasonTLSNotVerified: the server answered without TLS, or with a
	// certificate that does not verify for the host name.
	ReasonTLSNotVerified = "TLS_NOT_VERIFIED"
	// ReasonTimeout: no answer in time.
	ReasonTimeout = "TIMEOUT"
)

// Reach is what a probe found, as the engine reports it: Reason is empty
// when a probe passed.
type Reach struct{ Reason string }

// ReachError is a probe that failed for Reason. ADDRESS_REFUSED is also
// ErrAddressInvalid (problem ADDRESS_INVALID); every other reason is
// ErrUnreachable.
type ReachError struct{ Reason string }

func (e *ReachError) Error() string {
	if e.Reason == ReasonAddressRefused {
		return ErrAddressInvalid.Error()
	}
	return ErrUnreachable.Error() + " (" + e.Reason + ")"
}

// Is matches ErrAddressInvalid for ADDRESS_REFUSED, ErrUnreachable for
// the others.
func (e *ReachError) Is(target error) bool {
	if e.Reason == ReasonAddressRefused {
		return target == ErrAddressInvalid
	}
	return target == ErrUnreachable
}

// ReachOf is the report for a probe's outcome err, and false when there is
// none to make: an address that failed the shape rules is never reported,
// and neither is a failure that is not the database's (a broken random
// source).
func ReachOf(err error) (Reach, bool) {
	if err == nil {
		return Reach{}, true
	}
	var re *ReachError
	if errors.As(err, &re) {
		return Reach{Reason: re.Reason}, true
	}
	return Reach{}, false
}

// Prober checks a collected address the way the contract says, with logins
// bound to fail. It never holds the agent's password: Probe takes none, and
// every login it makes sends a random one (CONTRACT.md, The engine and a
// connect-only code, The probe, with a wrong password).
type Prober struct {
	// Resolver resolves the host once; SystemResolver outside tests.
	Resolver Resolver
	// Dial opens the TCP connection to the checked address; nil dials it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Roots, when set, replace every root the server's certificate is
	// verified against; nil uses the system's, plus Supabase's roots for a
	// Supabase host.
	Roots *x509.CertPool
	// SupabaseRoots stand in for Supabase's root certificates, which the
	// probe trusts for Supabase hosts (package supabaseca); empty is the
	// real ones. Tests set test CAs.
	SupabaseRoots []*x509.Certificate
}

// Probed is a probe that passed: the address the host resolved to, and
// whether channel binding works there.
type Probed struct {
	IP             netip.Addr
	ChannelBinding bool
}

// Probe checks a's shape and resolves its host (Resolve), then probes the
// address it resolved to (ProbeAt).
func (p Prober) Probe(ctx context.Context, a Address, user string) (Probed, error) {
	ip, err := p.Resolve(ctx, a)
	if err != nil {
		return Probed{}, err
	}
	return p.ProbeAt(ctx, a, ip, user)
}

// Resolve checks a's shape (ErrAddressInvalid), resolves its host once and
// refuses any address outside global unicast (ADDRESS_REFUSED); a host
// that resolves to nothing is NO_ROUTE. It returns the address to connect
// to.
func (p Prober) Resolve(ctx context.Context, a Address) (netip.Addr, error) {
	if err := a.Check(); err != nil {
		return netip.Addr{}, err
	}
	ip, err := pick(ctx, p.resolver(), a.Host)
	switch {
	case errors.Is(err, ErrAddressInvalid):
		return netip.Addr{}, &ReachError{Reason: ReasonAddressRefused}
	case err != nil:
		return netip.Addr{}, &ReachError{Reason: ReasonNoRoute}
	}
	return ip, nil
}

// ProbeAt tries logins as user with a random password to ip, which Resolve
// returned for a, the host name kept for TLS, with sslmode=verify-full:
// first with channel_binding=require, then without. A login refused for
// its password proves the server is reachable and its certificate
// verifies; otherwise a *ReachError says why none did.
func (p Prober) ProbeAt(ctx context.Context, a Address, ip netip.Addr, user string) (Probed, error) {
	var last error
	for _, binding := range []bool{true, false} {
		err := p.login(ctx, a, ip, user, binding)
		if proves(binding, err) {
			return Probed{IP: ip, ChannelBinding: binding}, nil
		}
		last = err
		if unreachable(err) {
			break
		}
	}
	return Probed{}, &ReachError{Reason: reasonOf(last)}
}

func (p Prober) resolver() Resolver {
	if p.Resolver == nil {
		return SystemResolver{}
	}
	return p.Resolver
}

// reasonOf is why a probe login that proved nothing failed: TIMEOUT for no
// answer in time, TLS_NOT_VERIFIED for a server without TLS or with a
// certificate that does not verify, NO_ROUTE otherwise.
func reasonOf(err error) string {
	var (
		ne      net.Error
		verify  *tls.CertificateVerificationError
		host    x509.HostnameError
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return ReasonTimeout
	case errors.As(err, &verify) || errors.As(err, &host) || errors.As(err, &unknown) || errors.As(err, &invalid),
		err != nil && strings.Contains(err.Error(), serverRefusedTLS):
		return ReasonTLSNotVerified
	}
	return ReasonNoRoute
}

// serverRefusedTLS is pgconn's error for a server that answered the TLS
// request with no.
const serverRefusedTLS = "server refused TLS connection"

// login tries one login bound to fail and closes it at once.
func (p Prober) login(ctx context.Context, a Address, ip netip.Addr, user string, binding bool) error {
	password := make([]byte, probePasswordBytes)
	if _, err := rand.Read(password); err != nil {
		return err
	}
	cfg, err := p.connConfig(a, ip, user, hex.EncodeToString(password), binding)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
}

// connConfig is the connection to a as user with password, made to ip only.
func (p Prober) connConfig(a Address, ip netip.Addr, user, password string, binding bool) (*pgx.ConnConfig, error) {
	cfg, err := pgdial.ConnConfigTrusting(ConnString(a, user, password, binding), p.supabaseRoots()...)
	if err != nil {
		return nil, err
	}
	pinned := ip.String()
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{pinned}, nil }
	if p.Dial != nil {
		cfg.DialFunc = p.Dial
	}
	if p.Roots != nil {
		setRoots(&cfg.Config, p.Roots)
	}
	return cfg, nil
}

// supabaseRoots are the roots the probe trusts for Supabase hosts.
func (p Prober) supabaseRoots() []*x509.Certificate {
	if len(p.SupabaseRoots) == 0 {
		return supabaseca.Roots()
	}
	return p.SupabaseRoots
}

// setRoots verifies every TLS attempt of cfg against roots.
func setRoots(cfg *pgconn.Config, roots *x509.CertPool) {
	set := func(t *tls.Config) {
		if t != nil {
			t.RootCAs = roots
		}
	}
	set(cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		set(fb.TLSConfig)
	}
}

// ConnString is the agent's connection string for a: user and password at
// a's host, port and database, with sslmode=verify-full and, when binding,
// channel_binding=require. Nothing from the connect service but the checked
// address goes in it. It names no sslrootcert: for a Supabase host the
// engine trusts Supabase's roots when it opens the connection (pgdial).
func ConnString(a Address, user, password string, binding bool) string {
	q := url.Values{}
	q.Set(paramSSLMode, sslVerifyFull)
	if binding {
		q.Set(paramChannelBinding, bindingRequire)
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(a.Host, strconv.Itoa(a.Port)),
		Path:     "/" + a.Database,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// LoginUser is the user the agent's role logs in as at a: <role>.<ref>
// through Supabase's pooler, the role otherwise.
func LoginUser(a Address, role string) string {
	if a.SupabaseRef != "" && strings.HasSuffix(strings.ToLower(a.Host), supabasePooler) {
		return role + "." + a.SupabaseRef
	}
	return role
}

// proves reports whether a probe login's error proves the candidate: with
// channel binding only a refused password (28P01) does; without, any
// refusal of the login (class 28, or Supabase's pooler not knowing the
// user), since pgx sends the startup message only after a TLS handshake
// whose certificate verified for the host name.
func proves(binding bool, err error) bool {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}
	if binding {
		return pg.Code == sqlstateInvalidPassword
	}
	return strings.HasPrefix(pg.Code, sqlstateClassAuth) || (pg.Code == sqlstateInternal && strings.Contains(pg.Message, supavisorNoTenant))
}

// unreachable is a login that reached no server: the dial failed or timed
// out (pgx joins one error per address).
func unreachable(err error) bool {
	switch e := err.(type) { //nolint:errorlint // walks the tree one level at a time
	case nil:
		return false
	case interface{ Unwrap() []error }:
		errs := e.Unwrap()
		for _, x := range errs {
			if !unreachable(x) {
				return false
			}
		}
		return len(errs) > 0
	case *net.OpError:
		return e.Op == "dial"
	}
	if u := errors.Unwrap(err); u != nil {
		return unreachable(u)
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
