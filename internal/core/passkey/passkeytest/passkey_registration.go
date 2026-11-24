package passkeytest

import (
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// ParseRegistrationRequest decodes a registration page fragment, with or
// without the leading '#'.
func ParseRegistrationRequest(fragment string) (passkey.RegistrationRequest, error) {
	var r passkey.RegistrationRequest
	if err := passkey.DecodeCode(passkey.RegistrationRequestPrefix, strings.TrimPrefix(fragment, "#"), &r); err != nil {
		return passkey.RegistrationRequest{}, err
	}
	return r, r.Validate()
}
