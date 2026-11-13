package main

import (
	"context"
	"errors"
	"net/url"
	"strings"

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
	bindingRequire      = "require"
)

// hardenedCredential is the agent's connection string for a role whose
// password comes from a SCRAM verifier in a setup code (CONTRACT.md, The
// setup code, verifier). The verifier is sensitive: whoever holds it and
// sees one SCRAM exchange of the role can derive its ClientKey and log in.
// So the connection requires channel binding (SCRAM-SHA-256-PLUS, bound to
// the server's TLS certificate), with sslmode=verify-full where the
// server's certificate verifies, else sslmode=require (verify-ca and
// verify-full are never weakened).
// Each candidate is tried first with a login that is bound to fail (the
// new password is not set yet): only a refused password (28P01) proves
// the client got through TLS and channel binding. When none does (no TLS,
// a Unix socket, sslmode=disable, a pooler that does not offer channel
// binding, or the database cannot be reached) the connection string stays
// as it is: a credential that cannot log in would be worse.
func hardenedCredential(ctx context.Context, dial func(context.Context, string) error, dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	mode := q.Get(paramSSLMode)
	if mode == sslDisable || strings.HasPrefix(q.Get(paramHost), "/") || (u.Host == "" && q.Get(paramHost) == "") {
		return dsn
	}
	for _, m := range sslCandidates(mode) {
		q.Set(paramSSLMode, m)
		q.Set(paramChannelBinding, bindingRequire)
		u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
		candidate := u.String()
		// The assumption: a server answers 28P01 only after a SCRAM
		// exchange (Postgres, PgBouncer); a proxy that sent it before any
		// SASL message would pass the probe and leave a credential that
		// cannot log in.
		var pg *pgconn.PgError
		if err := dial(ctx, candidate); errors.As(err, &pg) && pg.Code == sqlstateInvalidPassword {
			return candidate
		}
	}
	return dsn
}

// sslCandidates are the sslmodes to try, strongest first, never weaker
// than the admin's mode: verify-full, then verify-ca when that was given,
// else require (which adds only channel binding to what prefer gave).
func sslCandidates(mode string) []string {
	switch mode {
	case sslVerifyFull:
		return []string{sslVerifyFull}
	case sslVerifyCA:
		return []string{sslVerifyFull, sslVerifyCA}
	}
	return []string{sslVerifyFull, sslRequire}
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
