package setup

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
)

// The Update check on the connect page (CONTRACT.md, Connect, Update on the
// connect page): the passkey list Check returns for a code with a target,
// and RevokePasskey, which removes one with the admin connection alone.

// ActivePasskey is an active passkey's public data, never key material.
type ActivePasskey struct {
	CredentialID []byte
	Label        string
	// RPID is the relying party the passkey belongs to: basaltvault.app
	// for the portal's, localhost for the local pages'.
	RPID       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// PortalRPID is the relying party of the portal's passkeys.
const PortalRPID = passkey.RPID

// AcceptsTrustRoot reports whether a certificate authority the person
// trusted on the connect page (trustRoot) may be used for d: a connect-only
// code, or a code with a target that carries engine, whose engine checks
// the certificate itself before it replaces its pin (CONTRACT.md, A
// changed certificate on persona 2). Any other code with a trustRoot is
// refused TRUST_ROOT_MISMATCH by the caller.
func (d Description) AcceptsTrustRoot() bool { return d.Target == nil || d.EngineKey != "" }

// Revoked is what RevokePasskey did.
type Revoked struct {
	// Remaining are the active passkeys of the portal (RP ID
	// basaltvault.app) left, read in the revocation's transaction.
	Remaining []ActivePasskey
	// Lines are fixed sentences for the person.
	Lines []string
}

// RevokePasskey removes the active passkey credentialID with the admin
// connection conn opened, for the Update on the connect page. It runs the
// checks Check runs for the code that need no state of the setup: Describe's
// (the code is live), the connection's database against the code's target
// (TARGET_MISMATCH) and the guard's prefix (PREFIX_MISMATCH). A
// connect-only code is refused INVALID: only a code with a target has a
// database to name. Then, in one transaction,
// basalt_meta.revoke_passkey(credentialID, true): the admin login is what
// allows it, so the last passkey can go. A credentialID that is not an
// active passkey is ANSWERS_INVALID, nothing changed. A refusal is an
// *Error.
func RevokePasskey(ctx context.Context, conn *pgx.Conn, req Request, credentialID []byte) (Revoked, error) {
	r, err := contract.RevokePasskey(ctx, setupstore.Port(conn), adminAt(conn), contractRequest(req), credentialID)
	if err != nil {
		return Revoked{}, asError(err)
	}
	out := Revoked{Lines: r.Lines}
	for _, k := range r.Remaining {
		out.Remaining = append(out.Remaining, ActivePasskey{CredentialID: bytes.Clone(k.ID), Label: k.Label, RPID: k.RPID, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt})
	}
	return out, nil
}
