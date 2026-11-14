package passkey_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

func fixedChallenge() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// The same vector as web/lib/manage.test.mjs.
func TestCheckChallengeVector(t *testing.T) {
	t.Parallel()
	require.Equal(t, "da15f26856ebfb64b0b6e248d91c0969cc1724c608287249425d9d06c4e4ced6",
		hex.EncodeToString(passkey.CheckChallenge(fixedChallenge())))
}

func checkAnswer(t *testing.T, req passkey.CheckRequest, found ...*passkeytest.Authenticator) passkey.CheckResponse {
	t.Helper()
	resp := passkey.CheckResponse{Challenge: req.Challenge, Found: []passkey.CheckedAssertion{}, Missing: []passkey.Bytes{}}
	for _, a := range found {
		as := sign(t, a, passkey.CheckChallenge(req.Challenge), passkeytest.FlagsUPUV, nil)
		resp.Found = append(resp.Found, passkey.CheckedAssertion{
			CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData,
			ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
		})
	}
	return resp
}

func TestVerifyCheck(t *testing.T) {
	t.Parallel()
	laptop := newAuthenticator(t, passkey.Production)
	phone := newAuthenticator(t, passkey.Production)
	creds := []passkey.Credential{laptop.Credential(), phone.Credential()}
	req, err := passkey.NewCheckRequest(bytes.NewReader(fixedChallenge()), []passkey.Labeled{
		{CredentialID: laptop.ID, Label: "laptop"}, {CredentialID: phone.ID, Label: "phone"},
	})
	require.NoError(t, err)

	link, err := req.URL(passkey.Origin + "/")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(link, "https://portal.basaltvault.app/passkeys/check#1."), link)

	resp := checkAnswer(t, req, laptop)
	resp.Missing = []passkey.Bytes{phone.ID}
	code, err := resp.Code()
	require.NoError(t, err)
	parsed, err := passkey.ParseCheckResponse(" " + code + "\n")
	require.NoError(t, err)
	found, err := passkey.VerifyCheck(req, parsed, creds)
	require.NoError(t, err)
	require.Equal(t, map[string]bool{passkey.Bytes(laptop.ID).String(): true}, found)

	t.Run("another link's code", func(t *testing.T) {
		t.Parallel()
		other := req
		other.Challenge = bytes.Repeat([]byte{1}, 32)
		_, err := passkey.VerifyCheck(other, parsed, creds)
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
	t.Run("a passkey the link did not ask for", func(t *testing.T) {
		t.Parallel()
		_, err := passkey.VerifyCheck(req, parsed, creds[1:])
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
	t.Run("an approval signature is not a check", func(t *testing.T) {
		t.Parallel()
		as := sign(t, phone, approval.Challenge(`{"kind": "APPROVE"}`), passkeytest.FlagsUPUV, nil)
		bad := passkey.CheckResponse{Challenge: req.Challenge, Found: []passkey.CheckedAssertion{{
			CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
		}}}
		_, err := passkey.VerifyCheck(req, bad, creds)
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
}

func TestCheckChallengeIsNeverABinding(t *testing.T) {
	t.Parallel()
	// Approval and revert challenges hash a JSON binding text; the check
	// challenge hashes a text with its own prefix, so the two never meet.
	text := "basalt-passkey-check.1." + passkey.Bytes(fixedChallenge()).String()
	require.Equal(t, approval.Challenge(text), passkey.CheckChallenge(fixedChallenge()))
	require.False(t, strings.HasPrefix(text, "{"))
}

func TestNewCheckRequestBounds(t *testing.T) {
	t.Parallel()
	_, err := passkey.NewCheckRequest(bytes.NewReader(fixedChallenge()), nil)
	require.Error(t, err)
}

func TestForgetLink(t *testing.T) {
	t.Parallel()
	link, err := passkey.ForgetRequest{
		Mode:     passkey.ModeForget,
		Removed:  []passkey.Removed{{CredentialID: []byte{1, 2, 3}, Label: "old"}},
		Accepted: []passkey.Bytes{},
	}.URL("http://localhost:8787")
	require.NoError(t, err)
	frag, ok := strings.CutPrefix(link, "http://localhost:8787/passkeys/forget#")
	require.True(t, ok, link)
	var got map[string]any
	require.NoError(t, passkey.DecodeCode(passkey.ManageRequestPrefix, frag, &got))
	require.Equal(t, map[string]any{
		"mode": "FORGET", "removed": []any{map[string]any{"credentialId": "AQID", "label": "old"}}, "accepted": []any{},
	}, got)
}
