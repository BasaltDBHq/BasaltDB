package setup

import (
	"bytes"
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The Update check on the connect page (CONTRACT.md, Connect, Update on the
// connect page): RevokePasskey removes an active passkey with the admin
// connection alone.

// ContractRevoked is what RevokePasskey did (pkg/setup's Revoked).
type ContractRevoked struct {
	// Remaining are the active passkeys of the portal left, read in the
	// revocation's transaction.
	Remaining []guardmodel.RegisteredPasskey
	Lines     []string
}

// msgPasskeyNotActive is the contract's ANSWERS_INVALID message for a
// passkey that is not active.
const msgPasskeyNotActive = "This passkey is not active any more. Nothing changed."

// RevokePasskey removes the active passkey credentialID on the admin
// connection conn, which points at at, after the checks of the code that
// need no state of the setup: Describe's, the connection's database against
// the code's target and the guard's prefix. A connect-only code is refused
// INVALID. Then, in one transaction, revoke_passkey(credentialID, true). A
// credentialID that is not an active passkey is ANSWERS_INVALID.
func (c Contract) RevokePasskey(ctx context.Context, conn Querier, at ConnConfig, req ContractRequest, credentialID []byte) (ContractRevoked, error) {
	s, err := NewSetuprun(c.be, req.Code, req.Now)
	if err != nil {
		return ContractRevoked{}, err
	}
	if s.P.Target == nil {
		return ContractRevoked{}, &SetuprunRefusalError{Code: string(setupcode.RefusalInvalid), Message: "a connect-only setup code names no database to remove a passkey from; ask your agent for a new one"}
	}
	if err := CheckConnTarget(s.P, at); err != nil {
		return ContractRevoked{}, err
	}
	installed, err := c.be.InstalledPrefix(ctx, conn)
	if err != nil {
		return ContractRevoked{}, err
	}
	// The prefix check alone of the database's state: the role is given as
	// existing so no other refusal of step 4 applies here.
	if err := setupcode.CheckDatabase(s.P, setupcode.Database{Prefix: installed, Roles: []string{s.P.Role()}}); err != nil {
		return ContractRevoked{}, err
	}
	var out ContractRevoked
	err = c.be.BeginFunc(ctx, conn, func(tx Querier) error {
		active, err := c.activePasskeys(ctx, tx)
		if err != nil {
			return err
		}
		label, found := "", false
		for _, k := range active {
			if bytes.Equal(k.ID, credentialID) {
				label, found = k.Label, true
			}
		}
		if !found {
			return &SetuprunRefusalError{Code: SetuprunCodeAnswersInvalid, Message: msgPasskeyNotActive}
		}
		if _, err := c.be.RevokePasskey(ctx, tx, credentialID, true); err != nil {
			return err
		}
		left, err := c.activePasskeys(ctx, tx)
		if err != nil {
			return err
		}
		for _, k := range left {
			if k.RPID == passkey.RPID {
				out.Remaining = append(out.Remaining, k)
			}
		}
		out.Lines = revokedLines(label, len(out.Remaining))
		return nil
	})
	if err != nil {
		return ContractRevoked{}, err
	}
	return out, nil
}

// revokedLines are the fixed sentences after a removal.
func revokedLines(label string, portal int) []string {
	out := []string{fmt.Sprintf("The passkey %s is removed: it can no longer approve or undo anything.", printablePasskeyLabel(label))}
	if portal == 0 {
		return append(out, "No passkey of this site is left: add one on this device before you approve.")
	}
	return out
}

// printablePasskeyLabel is label as a sentence shows it: quoted, a blank
// one named.
func printablePasskeyLabel(label string) string {
	if label == "" {
		return "without a name"
	}
	return fmt.Sprintf("%q", label)
}
