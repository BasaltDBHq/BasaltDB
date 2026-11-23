package setup

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
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

// activePasskeys are the database's active passkeys; none in a database
// with no guard yet.
func activePasskeys(ctx context.Context, q guard.Querier) ([]ActivePasskey, error) {
	var installed bool
	// Plain SQL: a catalog presence check.
	if err := q.QueryRow(ctx, "SELECT pg_catalog.to_regclass('basalt_meta.passkeys') IS NOT NULL").Scan(&installed); err != nil {
		return nil, err
	}
	if !installed {
		return nil, nil
	}
	keys, err := guard.ActivePasskeys(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]ActivePasskey, 0, len(keys))
	for _, k := range keys {
		out = append(out, ActivePasskey{CredentialID: bytes.Clone(k.ID), Label: k.Label, RPID: k.RPID, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt})
	}
	return out, nil
}

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
	s, err := setuprun.New(store, req.Code, req.Now, true)
	if err != nil {
		return Revoked{}, asError(err)
	}
	if s.P.Target == nil {
		return Revoked{}, asError(&setuprun.RefusalError{Code: string(setupcode.RefusalInvalid), Message: "a connect-only setup code names no database to remove a passkey from; ask your agent for a new one"})
	}
	if err := setuprun.CheckConnTarget(s.P, conn.Config()); err != nil {
		return Revoked{}, asError(err)
	}
	installed, err := guard.InstalledPrefix(ctx, conn)
	if err != nil {
		return Revoked{}, asError(err)
	}
	// The prefix check alone of the database's state: the role is given as
	// existing so no other refusal of step 4 applies here.
	if err := setupcode.CheckDatabase(s.P, setupcode.Database{Prefix: installed, Roles: []string{s.P.Role()}}); err != nil {
		return Revoked{}, asError(err)
	}
	var out Revoked
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		active, err := activePasskeys(ctx, tx)
		if err != nil {
			return err
		}
		label, found := "", false
		for _, k := range active {
			if bytes.Equal(k.CredentialID, credentialID) {
				label, found = k.Label, true
			}
		}
		if !found {
			return &setuprun.RefusalError{Code: CodeAnswersInvalid, Message: msgPasskeyNotActive}
		}
		if _, err := guard.RevokePasskey(ctx, tx, credentialID, true); err != nil {
			return err
		}
		left, err := activePasskeys(ctx, tx)
		if err != nil {
			return err
		}
		for _, k := range left {
			if k.RPID == PortalRPID {
				out.Remaining = append(out.Remaining, k)
			}
		}
		out.Lines = revokedLines(label, len(out.Remaining))
		return nil
	})
	if err != nil {
		return Revoked{}, asError(err)
	}
	return out, nil
}

// msgPasskeyNotActive is the contract's ANSWERS_INVALID message for a
// passkey that is not active.
const msgPasskeyNotActive = "This passkey is not active any more. Nothing changed."

// revokedLines are the fixed sentences after a removal.
func revokedLines(label string, portal int) []string {
	out := []string{fmt.Sprintf("The passkey %s is removed: it can no longer approve or undo anything.", printable(label))}
	if portal == 0 {
		return append(out, "No passkey of this site is left: add one on this device before you approve.")
	}
	return out
}

// printable is label as a sentence shows it: quoted, a blank one named.
func printable(label string) string {
	if label == "" {
		return "without a name"
	}
	return fmt.Sprintf("%q", label)
}
