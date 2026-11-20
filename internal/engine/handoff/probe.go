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
// (problem DATABASE_UNREACHABLE_FROM_BOT).
var ErrUnreachable = errors.New("the database cannot be reached from the bot's machine with a verified certificate")

// Prober checks a collected address the way the contract says, with logins
// bound to fail. It never holds the agent's password: Probe takes none, and
// every login it makes sends a random one (CONTRACT.md, The engine and a
// connect-only code, The probe, with a wrong password).
type Prober struct {
	// Resolver resolves the host once; SystemResolver outside tests.
	Resolver Resolver
	// Dial opens the TCP connection to the checked address; nil dials it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Roots verify the server's certificate; nil uses the system's.
	Roots *x509.CertPool
}

// Probed is a probe that passed: the address the host resolved to, and
// whether channel binding works there.
type Probed struct {
	IP             netip.Addr
	ChannelBinding bool
}

// Probe checks a's shape, resolves its host once and refuses any address
// outside global unicast (ErrAddressInvalid), then tries logins as user with
// a random password to that address, the host name kept for TLS, with
// sslmode=verify-full: first with channel_binding=require, then without.
// A login refused for its password proves the server is reachable and its
// certificate verifies; ErrUnreachable when none does.
func (p Prober) Probe(ctx context.Context, a Address, user string) (Probed, error) {
	if err := a.Check(); err != nil {
		return Probed{}, err
	}
	ip, err := pick(ctx, p.resolver(), a.Host)
	switch {
	case errors.Is(err, ErrAddressInvalid):
		return Probed{}, err
	case err != nil:
		return Probed{}, ErrUnreachable
	}
	for _, binding := range []bool{true, false} {
		err := p.login(ctx, a, ip, user, binding)
		if proves(binding, err) {
			return Probed{IP: ip, ChannelBinding: binding}, nil
		}
		if unreachable(err) {
			break
		}
	}
	return Probed{}, ErrUnreachable
}

func (p Prober) resolver() Resolver {
	if p.Resolver == nil {
		return SystemResolver{}
	}
	return p.Resolver
}

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
	cfg, err := pgdial.ConnConfig(ConnString(a, user, password, binding))
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
// address goes in it.
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
