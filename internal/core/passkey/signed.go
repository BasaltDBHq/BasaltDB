package passkey

import (
	"errors"

	"github.com/google/uuid"
)

// SignedAssertion is the assertion a page posts after the person signs,
// in the pages' JSON. A page's signed response embeds it beside the id it
// signs for, under that id's own JSON name.
type SignedAssertion struct {
	CredentialID      Bytes `json:"credentialId"`
	AuthenticatorData Bytes `json:"authenticatorData"`
	ClientDataJSON    Bytes `json:"clientDataJson"`
	Signature         Bytes `json:"signature"`
}

// SignedAssertionOf is assertion a in the pages' JSON.
func SignedAssertionOf(a Assertion) SignedAssertion {
	return SignedAssertion{
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}
}

// Assertion returns the WebAuthn assertion the response carries.
func (s SignedAssertion) Assertion() Assertion {
	return Assertion{
		CredentialID:      s.CredentialID,
		AuthenticatorData: s.AuthenticatorData,
		ClientDataJSON:    s.ClientDataJSON,
		Signature:         s.Signature,
	}
}

// SignedResponse is a page's signed response: the id it signs for and the
// assertion. Its type embeds SignedAssertion and names the id's JSON field.
type SignedResponse interface {
	Signed() (uuid.UUID, SignedAssertion)
}

// ErrIncomplete is a signed response without its id or one of the
// assertion's fields.
var ErrIncomplete = errors.New("signed response is missing a field")

// DecodeSigned decodes the signed response a page posts into r, strictly
// (DecodeStrict: an unknown field is refused), and refuses one whose id is
// the nil id or whose assertion lacks a field with ErrIncomplete.
func DecodeSigned(raw []byte, r SignedResponse) error {
	if err := DecodeStrict(raw, r); err != nil {
		return err
	}
	id, a := r.Signed()
	if id == uuid.Nil || len(a.CredentialID) == 0 || len(a.AuthenticatorData) == 0 || len(a.ClientDataJSON) == 0 || len(a.Signature) == 0 {
		return ErrIncomplete
	}
	return nil
}
