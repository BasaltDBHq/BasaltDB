package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// The contract's test vector: the P-256 base point.
func TestCheckCodeTestVector(t *testing.T) {
	x, y := baseXY()
	require.Equal(t, "dbf5 ff76 2025 209d d866", CheckCode(x, y))
}

func TestCheckCodeOfCredential(t *testing.T) {
	x, y := baseXY()
	pub, err := PublicKeyFromXY(x, y)
	require.NoError(t, err)
	got, err := Credential{PublicKey: pub}.CheckCode()
	require.NoError(t, err)
	require.Equal(t, "dbf5 ff76 2025 209d d866", got)
}

func TestCheckCodeDiffersPerKey(t *testing.T) {
	x, y := baseXY()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	got, err := Credential{PublicKey: &k.PublicKey}.CheckCode()
	require.NoError(t, err)
	require.NotEqual(t, CheckCode(x, y), got)
	require.Regexp(t, `^[0-9a-f]{4}( [0-9a-f]{4}){4}$`, got)
}

// baseXY is the P-256 base point's coordinates, the contract's test vector.
func baseXY() (x, y []byte) {
	p := elliptic.P256().Params()
	return p.Gx.FillBytes(make([]byte, coordLen)), p.Gy.FillBytes(make([]byte, coordLen))
}
