package passkey_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// pairingVectors is api/mcp/passkey/pairing-code.json, which the
// registration page's tests (web/lib/pairing.test.mjs) run too.
type pairingVectors struct {
	Codes []struct {
		Name         string        `json:"name"`
		Challenge    passkey.Bytes `json:"challenge"`
		CredentialID passkey.Bytes `json:"credentialId"`
		X            passkey.Bytes `json:"x"`
		Y            passkey.Bytes `json:"y"`
		Code         string        `json:"code"`
	} `json:"codes"`
	Normalise []struct {
		Input string  `json:"input"`
		Code  *string `json:"code"`
	} `json:"normalise"`
}

func readPairingVectors(t *testing.T) pairingVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../api/mcp/passkey/pairing-code.json")
	require.NoError(t, err)
	var v pairingVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.GreaterOrEqual(t, len(v.Codes), 3)
	return v
}

func TestPairingCodeVectors(t *testing.T) {
	t.Parallel()
	for _, c := range readPairingVectors(t).Codes {
		got := passkey.PairingCode(c.Challenge, c.CredentialID, c.X, c.Y)
		require.Equal(t, c.Code, got, c.Name)
		norm, ok := passkey.NormalizePairingCode(got)
		require.True(t, ok, c.Name)
		require.Equal(t, got[:4]+got[5:], norm, c.Name)
	}
}

func TestPairingCodeNormalises(t *testing.T) {
	t.Parallel()
	for _, c := range readPairingVectors(t).Normalise {
		got, ok := passkey.NormalizePairingCode(c.Input)
		if c.Code == nil {
			require.False(t, ok, "%q", c.Input)
			require.Empty(t, got, "%q", c.Input)
			continue
		}
		require.True(t, ok, "%q", c.Input)
		require.Equal(t, *c.Code, got, "%q", c.Input)
	}
}

// A different key, credential or challenge gives a different code: the
// code tells the person's registration from one another program posted.
func TestPairingCodeDependsOnEveryInput(t *testing.T) {
	t.Parallel()
	v := readPairingVectors(t).Codes[1]
	base := passkey.PairingCode(v.Challenge, v.CredentialID, v.X, v.Y)
	flip := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[0] ^= 1
		return out
	}
	require.NotEqual(t, base, passkey.PairingCode(flip(v.Challenge), v.CredentialID, v.X, v.Y))
	require.NotEqual(t, base, passkey.PairingCode(v.Challenge, flip(v.CredentialID), v.X, v.Y))
	require.NotEqual(t, base, passkey.PairingCode(v.Challenge, v.CredentialID, flip(v.X), v.Y))
	require.NotEqual(t, base, passkey.PairingCode(v.Challenge, v.CredentialID, v.X, flip(v.Y)))
}
