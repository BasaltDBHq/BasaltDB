package setup

import (
	"strings"
	"time"
)

// LoginTimeout bounds the agent's login that decides the code's kind.
const LoginTimeout = 15 * time.Second

// sqlstateInvalidPassword is a SCRAM exchange the server refused: with
// channel_binding=require the client only gets this far when the server
// offered SCRAM-SHA-256-PLUS over a TLS connection the client accepted.
const sqlstateInvalidPassword = "28P01"

// SQLStateClassAuth is the SQLSTATE class of a refused login:
// invalid_password (28P01) and invalid_authorization_specification (28000:
// no such role, a pg_hba refusal).
const SQLStateClassAuth = "28"

// SQLStateInternal is internal_error, which Supabase's pooler raises for a
// user it does not know (SupavisorNoTenant).
const SQLStateInternal = "XX000"

// SupavisorNoTenant is what Supabase's pooler answers (SQLSTATE XX000) for a
// user it does not know, such as an agent role not created yet.
const SupavisorNoTenant = "Tenant or user not found"

// LoginRefused reports whether err is the database refusing a login, on
// any connection: any class 28 error, or Supabase's pooler not knowing the
// user (XX000 with SupavisorNoTenant in the server's message, read through
// e). e is consulted only for an XX000.
func LoginRefused(e DBErrors, err error) bool {
	code := SQLStateOf(err)
	if strings.HasPrefix(code, SQLStateClassAuth) {
		return true
	}
	if code != SQLStateInternal {
		return false
	}
	message, _ := e.ServerMessage(err)
	return strings.Contains(message, SupavisorNoTenant)
}

// LoginProves reports whether err, the answer to a login bound to fail
// (its password is wrong) made with sslmode and, when binding,
// channel_binding=require, proves that connection works. With channel
// binding only a refused password (28P01) does, in any sslmode: the client
// gets that far only through TLS and channel binding. Without, only
// sslmode=verify-full counts, on any refusal of the login (LoginRefused):
// pgx sends the startup message only after a TLS handshake whose
// certificate verified for the host name, so the answer proves the
// certificate verifies.
//
// The assumption: a server answers 28P01 only after a SCRAM exchange
// (Postgres, PgBouncer); a proxy that sent it before any SASL message
// would pass a channel binding probe and leave a credential that cannot
// log in.
func LoginProves(e DBErrors, sslmode string, binding bool, err error) bool {
	if binding {
		return SQLStateOf(err) == sqlstateInvalidPassword
	}
	return sslmode == sslVerifyFull && LoginRefused(e, err)
}
