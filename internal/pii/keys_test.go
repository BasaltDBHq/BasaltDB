package pii_test

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/pii"
)

func TestNewKeysRefusesAWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, err := pii.NewKeys(make([]byte, n))
		require.Error(t, err, n)
	}
}

func TestNewKeysDoesNotKeepTheCallersSlice(t *testing.T) {
	master := append([]byte(nil), testMaster...)
	k := newKeys(t, master)
	before, err := k.MakeToken(pii.EntityEmail, "a@b.example", "")
	require.NoError(t, err)
	for i := range master {
		master[i] = 0
	}
	after, err := k.MakeToken(pii.EntityEmail, "a@b.example", "")
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// The token key follows the design: k_type = HKDF(k_master, "basalt-tok:" +
// type + ":v1"), t = HMAC-SHA256(k_type, normalize(value)), id = base32(t)[:12].
func TestTokenKeyDerivationMatchesTheDesign(t *testing.T) {
	k := newKeys(t, testMaster)
	for _, typ := range pii.TokenTypes() {
		kt, err := hkdf.Key(sha256.New, testMaster, nil, fmt.Sprintf("basalt-tok:%s:v1", typ), sha256.Size)
		require.NoError(t, err)
		mac := hmac.New(sha256.New, kt)
		mac.Write([]byte(pii.Normalize(typ, "x", "")))
		want := base32.StdEncoding.EncodeToString(mac.Sum(nil))[:12]
		tok, err := k.MakeToken(typ, "x", "")
		require.NoError(t, err)
		require.Contains(t, tok.ID, want, typ)
	}
}

// The dictionary key is HKDF(k_master, "basalt-dict:v1"); a hash is the first
// 8 bytes of HMAC-SHA256 over a form prefix and the normalized value.
func TestDictionaryHashesMatchTheDesign(t *testing.T) {
	k := newKeys(t, testMaster)
	kd, err := hkdf.Key(sha256.New, testMaster, nil, "basalt-dict:v1", sha256.Size)
	require.NoError(t, err)
	h := func(s string) pii.Hash {
		mac := hmac.New(sha256.New, kd)
		mac.Write([]byte(s))
		return pii.Hash(binary.BigEndian.Uint64(mac.Sum(nil)[:8]))
	}
	require.Equal(t, h("g:alice tamm"), k.GenericHash("  Alice\tTAMM "))
	require.Equal(t, h("t:EMAIL:a@b.example"), k.TypedHash(pii.EntityEmail, "A@B.example", ""))
	require.Equal(t, h("t:PHONE:+447700900123"), k.TypedHash(pii.EntityPhone, "+44 7700 900123", ""))
}

func TestKeysNeverPrintKeyMaterial(t *testing.T) {
	k := newKeys(t, testMaster)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, k), fmt.Sprint(*k)} {
		require.NotContains(t, s, string(testMaster))
		require.Contains(t, s, "redacted")
	}
}

func TestKeyVersionIsOne(t *testing.T) {
	require.Equal(t, 1, pii.KeyVersion)
	require.Equal(t, 1, newKeys(t, testMaster).Version())
}
