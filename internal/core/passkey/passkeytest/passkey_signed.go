package passkeytest

import "github.com/basaltdbhq/basaltdb/internal/core/passkey"

// Signed is assertion a in the pages' JSON, for a test to post or relay.
func Signed(a passkey.Assertion) passkey.SignedAssertion {
	return passkey.SignedAssertion{
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}
}
