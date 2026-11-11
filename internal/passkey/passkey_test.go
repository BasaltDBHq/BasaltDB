package passkey_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

func newAuthenticator(t *testing.T, rp passkey.Relying) *passkeytest.Authenticator {
	t.Helper()
	a, err := passkeytest.New(rp)
	require.NoError(t, err)
	return a
}

func sign(t *testing.T, a *passkeytest.Authenticator, challenge []byte, flags byte, tamper func(*passkey.Assertion)) passkey.Assertion {
	t.Helper()
	as, err := a.Sign(challenge, flags, tamper)
	require.NoError(t, err)
	return as
}

func requireRejected(t *testing.T, err error, detail string) {
	t.Helper()
	require.ErrorIs(t, err, passkey.ErrRejected)
	require.ErrorContains(t, err, detail)
}

// The same cases the spike's TestQ5PasskeyApproval runs against
// basalt_meta.submit_approval.
func TestVerifyAssertion(t *testing.T) {
	t.Parallel()
	person := newAuthenticator(t, passkey.Production)
	cred := person.Credential()
	challenge := sha256.Sum256([]byte("binding text"))

	t.Run("valid", func(t *testing.T) {
		count, err := passkey.VerifyAssertion(cred, challenge[:], sign(t, person, challenge[:], passkeytest.FlagsUPUV, nil))
		require.NoError(t, err)
		require.Equal(t, person.Counter, count)
	})

	cases := []struct {
		name   string
		as     func() passkey.Assertion
		detail string
	}{
		{"another key signs", func() passkey.Assertion {
			forger := newAuthenticator(t, passkey.Production)
			forger.ID = person.ID
			return sign(t, forger, challenge[:], passkeytest.FlagsUPUV, nil)
		}, "bad passkey signature"},
		{"another credential id", func() passkey.Assertion {
			return sign(t, newAuthenticator(t, passkey.Production), challenge[:], passkeytest.FlagsUPUV, nil)
		}, "another passkey"},
		{"challenge for another action", func() passkey.Assertion {
			return sign(t, person, []byte("another action"), passkeytest.FlagsUPUV, nil)
		}, "client data does not match"},
		{"registration client data", func() passkey.Assertion {
			return sign(t, person, challenge[:], passkeytest.FlagsUPUV, func(as *passkey.Assertion) {
				as.ClientDataJSON = bytes.Replace(as.ClientDataJSON, []byte("webauthn.get"), []byte("webauthn.create"), 1)
			})
		}, "client data does not match"},
		{"another origin", func() passkey.Assertion {
			return sign(t, person, challenge[:], passkeytest.FlagsUPUV, func(as *passkey.Assertion) {
				as.ClientDataJSON = bytes.Replace(as.ClientDataJSON, []byte(passkey.Origin), []byte("https://evil.example"), 1)
			})
		}, "client data does not match"},
		{"user verification missing", func() passkey.Assertion {
			return sign(t, person, challenge[:], passkeytest.FlagUP, nil)
		}, "verification required"},
		{"wrong RP ID", func() passkey.Assertion {
			return sign(t, person, challenge[:], passkeytest.FlagsUPUV, func(as *passkey.Assertion) {
				h := sha256.Sum256([]byte("evil.example"))
				copy(as.AuthenticatorData, h[:])
			})
		}, "rpIdHash"},
		{"short authenticator data", func() passkey.Assertion {
			return sign(t, person, challenge[:], passkeytest.FlagsUPUV, func(as *passkey.Assertion) {
				as.AuthenticatorData = as.AuthenticatorData[:20]
			})
		}, "too short"},
		{"signature bit flipped", func() passkey.Assertion {
			as := sign(t, person, challenge[:], passkeytest.FlagsUPUV, nil)
			as.Signature[len(as.Signature)-1] ^= 0x01
			return as
		}, "bad passkey signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := passkey.VerifyAssertion(cred, challenge[:], tc.as())
			requireRejected(t, err, tc.detail)
		})
	}

	t.Run("replay is refused once the counter is stored", func(t *testing.T) {
		as := sign(t, person, challenge[:], passkeytest.FlagsUPUV, nil)
		count, err := passkey.VerifyAssertion(cred, challenge[:], as)
		require.NoError(t, err)
		stored := cred
		stored.SignCount = count
		_, err = passkey.VerifyAssertion(stored, challenge[:], as)
		requireRejected(t, err, "counter")
	})
	t.Run("a zero counter is accepted while the stored count is zero", func(t *testing.T) {
		zero := newAuthenticator(t, passkey.Production)
		zero.Counter = 0
		as, err := zero.Sign(challenge[:], passkeytest.FlagsUPUV, func(as *passkey.Assertion) {
			copy(as.AuthenticatorData[33:37], []byte{0, 0, 0, 0})
		})
		require.NoError(t, err)
		count, err := passkey.VerifyAssertion(zero.Credential(), challenge[:], as)
		require.NoError(t, err)
		require.Zero(t, count)
	})
}

func newRequest(t *testing.T) passkey.RegistrationRequest {
	t.Helper()
	req, err := passkey.NewRegistrationRequest(rand.Reader, "app", "BasaltDB · app")
	require.NoError(t, err)
	return req
}

func TestVerifyRegistration(t *testing.T) {
	t.Parallel()
	person := newAuthenticator(t, passkey.Production)
	req := newRequest(t)

	t.Run("valid, and the stored key verifies assertions", func(t *testing.T) {
		resp, err := person.Register(req, nil)
		require.NoError(t, err)
		cred, err := passkey.VerifyRegistration(req, resp, passkey.Production)
		require.NoError(t, err)
		require.Equal(t, person.ID, cred.ID)
		x, y, err := cred.XY()
		require.NoError(t, err)
		pub, err := passkey.PublicKeyFromXY(x, y)
		require.NoError(t, err)
		require.True(t, pub.Equal(&person.Key.PublicKey))

		challenge := sha256.Sum256([]byte("binding"))
		_, err = passkey.VerifyAssertion(cred, challenge[:], sign(t, person, challenge[:], passkeytest.FlagsUPUV, nil))
		require.NoError(t, err)
	})

	cases := []struct {
		name   string
		tamper func(*passkey.RegistrationResponse)
		rp     passkey.Relying
		detail string
	}{
		{"another challenge", func(r *passkey.RegistrationResponse) {
			r.ClientDataJSON = bytes.Replace(r.ClientDataJSON, []byte(req.Challenge.String()), []byte("AAAA"), 1)
		}, passkey.Production, "client data does not match"},
		{"assertion type", func(r *passkey.RegistrationResponse) {
			r.ClientDataJSON = bytes.Replace(r.ClientDataJSON, []byte("webauthn.create"), []byte("webauthn.get"), 1)
		}, passkey.Production, "client data does not match"},
		{"another relying party", nil, passkey.Relying{RPID: "evil.example", Origin: passkey.Origin}, "rpIdHash"},
		{"another origin", nil, passkey.Relying{RPID: passkey.RPID, Origin: "https://evil.example"}, "client data does not match"},
		{"no user verification", func(r *passkey.RegistrationResponse) {
			r.AuthenticatorData[32] &^= passkeytest.FlagUV
		}, passkey.Production, "verification required"},
		{"no attested credential", func(r *passkey.RegistrationResponse) {
			r.AuthenticatorData[32] &^= passkeytest.FlagAT
		}, passkey.Production, "attested credential id"},
		{"credential id swapped", func(r *passkey.RegistrationResponse) {
			r.CredentialID = []byte("someone else's id")
		}, passkey.Production, "attested credential id"},
		{"RS256", func(r *passkey.RegistrationResponse) {
			r.PublicKeyAlgorithm = -257
		}, passkey.Production, "ES256"},
		{"garbage key", func(r *passkey.RegistrationResponse) {
			r.PublicKey = []byte("not a key")
		}, passkey.Production, "SubjectPublicKeyInfo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := person.Register(req, tc.tamper)
			require.NoError(t, err)
			_, err = passkey.VerifyRegistration(req, resp, tc.rp)
			requireRejected(t, err, tc.detail)
		})
	}
}

func TestRegistrationCodes(t *testing.T) {
	t.Parallel()
	req := newRequest(t)
	frag, err := req.Fragment()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(frag, passkey.RegistrationRequestPrefix))
	got, err := passkey.ParseRegistrationRequest("#" + frag)
	require.NoError(t, err)
	require.Equal(t, req, got)

	resp, err := newAuthenticator(t, passkey.Production).Register(req, nil)
	require.NoError(t, err)
	code, err := resp.Code()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(code, passkey.RegistrationResponsePrefix))
	back, err := passkey.ParseRegistrationResponse("  " + code + "\n")
	require.NoError(t, err)
	require.Equal(t, resp, back)

	bad := []struct{ name, code, detail string }{
		{"wrong prefix", "basalt-approval.1.e30", "must start with"},
		{"padding", passkey.RegistrationResponsePrefix + "e30=", "base64url"},
		{"standard alphabet", passkey.RegistrationResponsePrefix + "+/", "base64url"},
		{"unknown field", passkey.RegistrationResponsePrefix + passkey.Bytes(`{"extra":1}`).String(), "unknown field"},
		{"too long", passkey.RegistrationResponsePrefix + strings.Repeat("A", 70000), "longer"},
	}
	for _, tc := range bad {
		_, err := passkey.ParseRegistrationResponse(tc.code)
		requireRejected(t, err, tc.detail)
	}

	_, err = passkey.ParseRegistrationRequest(passkey.RegistrationRequestPrefix + passkey.Bytes(`{"challenge":"AA","userId":"AA","userName":"a","displayName":"a"}`).String())
	requireRejected(t, err, "32-byte challenge")
	_, err = passkey.NewRegistrationRequest(rand.Reader, "", "x")
	requireRejected(t, err, "labels")
}

func TestBytesJSON(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(struct {
		B passkey.Bytes `json:"b"`
	}{B: []byte{0xfb, 0xff}})
	require.NoError(t, err)
	require.JSONEq(t, `{"b":"-_8"}`, string(raw))
	var back struct {
		B passkey.Bytes `json:"b"`
	}
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Equal(t, passkey.Bytes{0xfb, 0xff}, back.B)
	require.Error(t, json.Unmarshal([]byte(`{"b":"-_8="}`), &back))
	require.Error(t, json.Unmarshal([]byte(`{"b":1}`), &back))
}

func TestLocal(t *testing.T) {
	t.Parallel()
	rp, err := passkey.Local("http://localhost:8787")
	require.NoError(t, err)
	require.Equal(t, passkey.Relying{RPID: "localhost", Origin: "http://localhost:8787"}, rp)
	for _, bad := range []string{"https://localhost:8787", "http://localhost", "http://127.0.0.1:8787", "http://localhost:8787/", "http://evil.localhost:1", "http://localhost:99999"} {
		_, err := passkey.Local(bad)
		require.Error(t, err, bad)
	}
}

func TestPublicKeyFromXY(t *testing.T) {
	t.Parallel()
	_, err := passkey.PublicKeyFromXY(make([]byte, 32), make([]byte, 32))
	requireRejected(t, err, "P-256")
	_, err = passkey.PublicKeyFromXY(make([]byte, 31), make([]byte, 32))
	requireRejected(t, err, "32 bytes")
}
