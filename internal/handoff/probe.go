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

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/setup"

	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
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
	// ReasonTrustRootMismatch: the address came with a certificate
	// authority the person trusted on the connect page, and the server
	// presents another one to this machine (or one its certificate does not
	// verify against).
	ReasonTrustRootMismatch = "TRUST_ROOT_MISMATCH"
)

// ErrTrustRootMismatch is a probe whose server presents another chain top
// than the one the person approved on the connect page (problem
// TRUST_ROOT_MISMATCH): nothing is pinned and no login is tried.
var ErrTrustRootMismatch = errors.New("the database presents another certificate authority to this machine than the one trusted on the connect page")

// Reach is what a probe found, as the engine reports it: Reason is empty
// when a probe passed.
type Reach struct{ Reason string }

// ReachError is a probe that failed for Reason. ADDRESS_REFUSED is also
// ErrAddressInvalid (problem ADDRESS_INVALID), TRUST_ROOT_MISMATCH is
// ErrTrustRootMismatch; every other reason is ErrUnreachable.
type ReachError struct{ Reason string }

func (e *ReachError) Error() string {
	switch e.Reason {
	case ReasonAddressRefused:
		return setupcode.ErrAddressInvalid.Error()
	case ReasonTrustRootMismatch:
		return ErrTrustRootMismatch.Error()
	}
	return ErrUnreachable.Error() + " (" + e.Reason + ")"
}

// Is matches ErrAddressInvalid for ADDRESS_REFUSED, ErrTrustRootMismatch
// for TRUST_ROOT_MISMATCH, ErrUnreachable for the others.
func (e *ReachError) Is(target error) bool {
	switch e.Reason {
	case ReasonAddressRefused:
		return target == setupcode.ErrAddressInvalid
	case ReasonTrustRootMismatch:
		return target == ErrTrustRootMismatch
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
	// Resolver resolves the host once; internal/app gives
	// sysdns.Resolver. It is required to resolve.
	Resolver Resolver
	// Dial opens the TCP connection to the checked address; nil dials it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// ReadChain reads the chain host presents at ip and port with the TLS
	// handshake alone, over dial (nil: the system's TCP), connecting to ip
	// whatever address is asked for. It is required to read a chain;
	// internal/app gives handoffnet.ReadChain.
	ReadChain func(ctx context.Context, dial trustpin.Dial, ip netip.Addr, host string, port int) ([]*x509.Certificate, error)
	// Roots, when set, replace every root the server's certificate is
	// verified against; nil uses the system's, plus the roots of the trust
	// profile that matches the host (Supabase, Amazon RDS, the operator's).
	Roots *x509.CertPool
	// Profiles are the trust profiles the probe uses (package
	// trustprofile); nil is Trust's. Tests give test CAs.
	Profiles *trustprofile.Set
	// Trust is the trust profiles the engine holds now (the built-in ones
	// and the operator's); nil is the built-in ones. internal/app gives the
	// engine's own.
	Trust func() *trustprofile.Set
	// Login makes one login with dsn, trusting set (nil: the engine's own
	// trust), to the address ip only, over dial (nil dials) and, when roots
	// is set, verifying the server's certificate against roots alone; it
	// closes the connection at once when the login succeeds. The database's
	// refusal comes back as an error that carries its SQLSTATE (a
	// SQLState() string method), as the Postgres driver's does. It is
	// required to probe a login; internal/app gives the Postgres adapter's.
	Login func(ctx context.Context, dsn string, set *trustprofile.Set, ip string, dial func(ctx context.Context, network, addr string) (net.Conn, error), roots *x509.CertPool) error
	// Now is the clock certificates are checked at; nil is time.Now.
	Now func() time.Time
	// Errors reads the server's message of a refused login (Supabase's
	// pooler not knowing the user); internal/app gives the Postgres
	// adapter's. It is read only for an internal_error answer.
	Errors setup.DBErrors
}

// Pin is a certificate authority the person trusted on the connect page
// that this machine's own reading of the server's chain confirmed (Approve):
// the pin for the host, held in memory until the person's yes writes it.
// The zero Pin is none: the server's certificate verifies without one.
type Pin struct {
	Profile *trustprofile.Profile
	Top     *x509.Certificate
	// CAOnly: the leaf does not name the host, so the pin verifies the
	// chain alone (verify: ca).
	CAOnly bool
}

// Approve is what the engine makes of approved, the SHA-256 of the chain
// top the person trusted on the connect page for a's host, which ip
// resolved to (CONTRACT.md, Pinning from the connect page). The engine reads the chain itself, with the TLS
// handshake alone, over its own network: no startup message, no user, no
// password. The zero Pin, with no reading, when a trust profile covers the
// host or Roots replace every root: the engine's own trust decides, and the
// approval adds nothing. The zero Pin too when the chain verifies against
// the system's authorities. Otherwise the pin for the chain's top, only
// when its SHA-256 is approved and the chain verifies against it
// (TRUST_ROOT_MISMATCH): the connect service can never add trust that this
// check did not find itself.
func (p Prober) Approve(ctx context.Context, a setupcode.Address, ip netip.Addr, approved string) (Pin, error) {
	if p.Roots != nil || p.profiles().For(a.Host) != nil {
		return Pin{}, nil
	}
	if p.ReadChain == nil {
		return Pin{}, errors.New("handoff: the prober has no chain reader")
	}
	chain, err := p.ReadChain(ctx, p.Dial, ip, a.Host, a.Port)
	switch {
	case errors.Is(err, trustpin.ErrNoTLS):
		return Pin{}, &ReachError{Reason: ReasonTLSNotVerified}
	case err != nil:
		return Pin{}, &ReachError{Reason: reasonOf(err)}
	}
	seen, prof, err := trustpin.Approved(chain, a.Host, p.now(), approved)
	switch {
	case seen.System:
		return Pin{}, nil
	case errors.Is(err, trustpin.ErrPublic):
		// A public authority's certificate failed on the name: no pin can
		// fix that, and none is made.
		return Pin{}, &ReachError{Reason: ReasonTLSNotVerified}
	case errors.Is(err, trustpin.ErrMismatch), errors.Is(err, trustpin.ErrNotPinnable):
		return Pin{}, &ReachError{Reason: ReasonTrustRootMismatch}
	case err != nil:
		return Pin{}, err
	}
	return Pin{Profile: prof, Top: seen.Top, CAOnly: !seen.Full}, nil
}

// Repin is Approve for a host the engine pinned itself (pin-<host>) whose
// server presents another chain top (CONTRACT.md, A changed certificate on
// persona 2): the engine's own pin is left out, so the chain is read and
// checked against approved, the SHA-256 the person trusted on the connect
// page. Another profile covering the host decides as in Approve, and then
// nothing is pinned (TRUST_ROOT_MISMATCH), and so does a chain that needs
// no pin: only a pin whose top has approved's SHA-256 comes back.
func (p Prober) Repin(ctx context.Context, a setupcode.Address, ip netip.Addr, approved string) (Pin, error) {
	own := trustprofile.PinName(trustprofile.NormalizeHost(a.Host))
	p.Profiles = p.profiles().Replacing(own, nil)
	pin, err := p.Approve(ctx, a, ip, approved)
	switch {
	case err != nil:
		return Pin{}, err
	case pin.Profile == nil || pin.Top == nil || trustprofile.DERSHA256(pin.Top) != approved:
		return Pin{}, &ReachError{Reason: ReasonTrustRootMismatch}
	}
	return pin, nil
}

func (p Prober) profiles() *trustprofile.Set {
	if p.Profiles != nil {
		return p.Profiles
	}
	if p.Trust != nil {
		return p.Trust()
	}
	return trustprofile.BuiltInSet()
}

func (p Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Probed is a probe that passed: the address the host resolved to, and
// whether channel binding works there.
type Probed struct {
	IP             netip.Addr
	ChannelBinding bool
}

// Probe checks a's shape and resolves its host (Resolve), then probes the
// address it resolved to (ProbeAt), with no pin.
func (p Prober) Probe(ctx context.Context, a setupcode.Address, user string) (Probed, error) {
	ip, err := p.Resolve(ctx, a)
	if err != nil {
		return Probed{}, err
	}
	return p.ProbeAt(ctx, a, ip, user, Pin{})
}

// Resolve checks a's shape (ErrAddressInvalid), resolves its host once and
// refuses any address outside global unicast (ADDRESS_REFUSED); a host
// that resolves to nothing is NO_ROUTE. It returns the address to connect
// to.
func (p Prober) Resolve(ctx context.Context, a setupcode.Address) (netip.Addr, error) {
	if err := a.Check(); err != nil {
		return netip.Addr{}, err
	}
	if p.Resolver == nil {
		return netip.Addr{}, errors.New("handoff: the prober has no resolver")
	}
	ip, err := Pick(ctx, p.Resolver, a.Host)
	switch {
	case errors.Is(err, setupcode.ErrAddressInvalid):
		return netip.Addr{}, &ReachError{Reason: ReasonAddressRefused}
	case err != nil:
		return netip.Addr{}, &ReachError{Reason: ReasonNoRoute}
	}
	return ip, nil
}

// ProbeAt tries logins as user with a random password to ip, which Resolve
// returned for a, the host name kept for TLS, with sslmode=verify-full:
// first with channel_binding=require, then without. With a pin (Approve),
// the certificate is verified against it as if it were written already. A
// login refused for its password proves the server is reachable and its
// certificate verifies; otherwise a *ReachError says why none did.
func (p Prober) ProbeAt(ctx context.Context, a setupcode.Address, ip netip.Addr, user string, pin Pin) (Probed, error) {
	var last error
	for _, binding := range []bool{true, false} {
		err := p.login(ctx, a, ip, user, binding, pin)
		if setup.LoginProves(p.Errors, sslVerifyFull, binding, err) {
			return Probed{IP: ip, ChannelBinding: binding}, nil
		}
		last = err
		if unreachable(err) {
			break
		}
	}
	return Probed{}, &ReachError{Reason: reasonOf(last)}
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
func (p Prober) login(ctx context.Context, a setupcode.Address, ip netip.Addr, user string, binding bool, pin Pin) error {
	password := make([]byte, probePasswordBytes)
	if _, err := rand.Read(password); err != nil {
		return err
	}
	set := p.Profiles
	if pin.Profile != nil {
		set = p.profiles().Replacing(pin.Profile.Name, pin.Profile)
	}
	if p.Login == nil {
		return errors.New("handoff: the prober has no connection config")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return p.Login(ctx, ConnString(a, user, hex.EncodeToString(password), binding), set, ip.String(), p.Dial, p.Roots)
}

// ConnString is the agent's connection string for a: user and password at
// a's host, port and database, with sslmode=verify-full and, when binding,
// channel_binding=require. Nothing from the connect service but the checked
// address goes in it. It names no sslrootcert: for a provider's host (Supabase,
// Amazon RDS) the engine trusts that provider's roots when it opens the
// connection (pgdial).
func ConnString(a setupcode.Address, user, password string, binding bool) string {
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
