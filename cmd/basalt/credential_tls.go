package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/supabase"

	"github.com/jackc/pgx/v5/pgconn"
)

// sqlstateInvalidPassword is a SCRAM exchange the server refused: with
// channel_binding=require the client only gets this far when the server
// offered SCRAM-SHA-256-PLUS over a TLS connection the client accepted.
const sqlstateInvalidPassword = "28P01"

// The connection string parameters init --remote hardens.
const (
	paramSSLMode        = "sslmode"
	paramChannelBinding = "channel_binding"
	paramHost           = "host"
	sslDisable          = "disable"
	sslVerifyCA         = "verify-ca"
	sslVerifyFull       = "verify-full"
	sslRequire          = "require"
	sslDefault          = "prefer"
	bindingRequire      = "require"
)

// tlsCandidate is one sslmode, with or without channel_binding=require.
type tlsCandidate struct {
	mode    string
	binding bool
}

// protection is what hardenedCredential applied: the sslmode the agent's
// connection string ends with, whether it requires channel binding, and
// whether the hardening probed (false: nothing could be tried, see skip).
type protection struct {
	mode    string
	binding bool
	pooler  bool
	probed  bool
	skip    string
	changed bool
}

// hardenedCredential is the agent's connection string for a role whose
// password comes from a SCRAM verifier in a setup code (CONTRACT.md, The
// setup code, verifier). The verifier is sensitive: whoever holds it and
// sees one SCRAM exchange of the role can derive its ClientKey and log in.
// It keeps the strongest protection it can confirm, in this order:
//  1. sslmode=verify-full with channel binding (SCRAM-SHA-256-PLUS, bound to
//     the server's TLS certificate);
//  2. sslmode=verify-full alone, for a server whose certificate verifies but
//     that offers no channel binding (PgBouncer, Supabase's pooler): only a
//     verified certificate stops an active attacker who holds the verifier;
//  3. sslmode=verify-ca (when given) or require, with channel binding;
//  4. the connection string as built.
//
// verify-ca and verify-full are never weakened. Each candidate is tried
// first with a login that is bound to fail (the new password is not set
// yet). A candidate with channel binding counts only on a refused password
// (28P01), which proves the client got through TLS and channel binding.
// verify-full alone counts on any refusal of the login (class 28, or
// Supabase's pooler not knowing the role): pgx sends the startup message
// only after a TLS handshake whose certificate verified for the host name,
// so the answer proves the certificate verifies. When none counts (no TLS,
// a Unix socket, sslmode=disable, or the database cannot be reached) the
// connection string stays as it is: a credential that cannot log in would
// be worse.
func hardenedCredential(ctx context.Context, dial func(context.Context, string) error, dsn string) (string, protection) {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn, protection{mode: sslDefault, skip: "the connection string could not be read"}
	}
	q := u.Query()
	mode := q.Get(paramSSLMode)
	p := protection{
		mode: mode, binding: q.Get(paramChannelBinding) == bindingRequire,
		pooler: supabase.PoolerHost(u.Hostname()), // no channel binding there
	}
	if p.mode == "" {
		p.mode = sslDefault
	}
	switch {
	case mode == sslDisable:
		p.skip = "sslmode=disable"
		return dsn, p
	case strings.HasPrefix(q.Get(paramHost), "/"):
		p.skip = "a Unix socket"
		return dsn, p
	case u.Host == "" && q.Get(paramHost) == "":
		p.skip = "a local socket"
		return dsn, p
	}
	p.probed = true
	for _, c := range tlsCandidates(mode) {
		cq := u.Query()
		cq.Set(paramSSLMode, c.mode)
		if c.binding {
			cq.Set(paramChannelBinding, bindingRequire)
		}
		v := *u
		v.RawQuery = strings.ReplaceAll(cq.Encode(), "+", "%20")
		candidate := v.String()
		err := dial(ctx, candidate)
		if proves(c, err) {
			p.mode, p.binding = c.mode, c.binding || p.binding
			p.changed = candidate != dsn
			return candidate, p
		}
		if unreachable(err) {
			break
		}
	}
	return dsn, p
}

// tlsCandidates are the candidates to try, strongest first, never weaker
// than the admin's mode (see hardenedCredential).
func tlsCandidates(mode string) []tlsCandidate {
	switch mode {
	case sslVerifyFull:
		return []tlsCandidate{{sslVerifyFull, true}}
	case sslVerifyCA:
		return []tlsCandidate{{sslVerifyFull, true}, {sslVerifyFull, false}, {sslVerifyCA, true}}
	}
	return []tlsCandidate{{sslVerifyFull, true}, {sslVerifyFull, false}, {sslRequire, true}}
}

// proves reports whether a probe's error confirms candidate c (see
// hardenedCredential). The assumption: a server answers 28P01 only after a
// SCRAM exchange (Postgres, PgBouncer); a proxy that sent it before any SASL
// message would pass a channel binding probe and leave a credential that
// cannot log in.
func proves(c tlsCandidate, err error) bool {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}
	if c.binding {
		return pg.Code == sqlstateInvalidPassword
	}
	return c.mode == sslVerifyFull && (strings.HasPrefix(pg.Code, sqlstateClassAuth) ||
		(pg.Code == sqlstateInternal && strings.Contains(pg.Message, supavisorNoTenant)))
}

// unreachable is a probe that reached no server: every address pgx tried
// (it joins one error per host and address) failed to dial or timed out.
// One address reached (a TLS or a server error) keeps the probing going,
// as a dual-stack host without an IPv6 route or a multi-host URL with one
// replica down would otherwise stop it early.
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

// line is the one line init --remote prints about the agent's connection.
func (p protection) line() string {
	const prefix = "basalt: connection protected: "
	switch {
	case p.skip != "":
		return fmt.Sprintf("basalt: connection not protected further: %s (sslmode=%s kept)\n", p.skip, p.mode)
	case p.mode == sslVerifyFull && p.binding:
		return prefix + "database identity verified, channel binding on\n"
	case p.mode == sslVerifyFull && p.pooler:
		return prefix + "database identity verified (channel binding not available through the Supabase pooler)\n"
	case p.mode == sslVerifyFull && p.changed:
		return prefix + "database identity verified (the server offers no channel binding)\n"
	case p.mode == sslVerifyFull:
		return prefix + "database identity verified (sslmode=verify-full as given; channel binding could not be confirmed)\n"
	case p.mode == sslVerifyCA && p.binding:
		return prefix + "database certificate checked against its CA (host name not checked), channel binding on\n"
	case p.mode == sslVerifyCA:
		return prefix + "database certificate checked against its CA (sslmode=verify-ca as given; host name not checked, channel binding could not be confirmed)\n"
	case p.binding:
		return prefix + "encrypted with channel binding, but the database's certificate did not verify, so its identity is not checked " +
			"(to check it, " + connectPageTrust + ")\n"
	}
	return fmt.Sprintf("basalt: connection not protected further: TLS with a verified certificate or channel binding could not be confirmed "+
		"(no TLS, the certificate did not verify and no channel binding, or the database could not be reached; sslmode=%s kept; "+
		"for a certificate from the provider's own CA, "+connectPageTrust+")\n", p.mode)
}

// probeLogin tries a login with dsn and closes it: the error says how far
// it got (hardenedCredential).
func probeLogin(c *cliIO) func(context.Context, string) error {
	return func(ctx context.Context, dsn string) error {
		ctx, cancel := context.WithTimeout(ctx, loginTimeout)
		defer cancel()
		conn, err := c.dial(ctx, dsn)
		if err != nil {
			return err
		}
		return conn.Close(ctx)
	}
}
