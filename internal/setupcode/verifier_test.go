package setupcode_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

func TestVerifierFixtures(t *testing.T) {
	t.Parallel()
	for _, v := range loadFixtures(t).Verifiers {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			salt, err := base64.StdEncoding.DecodeString(v.Salt)
			require.NoError(t, err)
			got, err := setupcode.VerifierWithSalt(v.Password, salt)
			require.NoError(t, err)
			require.Equal(t, v.Verifier, got)
		})
	}
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()
	a, err := setupcode.NewVerifier("same password")
	require.NoError(t, err)
	b, err := setupcode.NewVerifier("same password")
	require.NoError(t, err)
	require.NotEqual(t, a, b, "a fresh random salt each time")
	require.True(t, setupcode.ValidVerifier(a), a)
	require.True(t, strings.HasPrefix(a, "SCRAM-SHA-256$4096:"))
	require.NotContains(t, a, "same password")
}

func TestVerifierRefusesBadInput(t *testing.T) {
	t.Parallel()
	_, err := setupcode.VerifierWithSalt("pw", make([]byte, 8))
	require.Error(t, err, "salt must be 16 bytes")
	_, err = setupcode.NewVerifier("")
	require.Error(t, err, "empty password")
	for _, pw := range []string{"pässword", "pass\u00a0word", "ｐａｓｓ"} {
		_, err = setupcode.NewVerifier(pw)
		require.Error(t, err, "non-ASCII password %q: SASLprep could change it", pw)
		require.NotContains(t, err.Error(), pw, "the error never holds the password")
	}
}

func TestValidVerifier(t *testing.T) {
	t.Parallel()
	good := loadFixtures(t).Verifiers[0].Verifier
	require.True(t, setupcode.ValidVerifier(good))
	for _, bad := range []string{
		"",
		strings.Replace(good, "$4096:", "$1000:", 1),
		strings.Replace(good, "SCRAM-SHA-256", "scram-sha-256", 1),
		good + "x",
		"md5" + strings.Repeat("0", 32),
	} {
		require.False(t, setupcode.ValidVerifier(bad), bad)
	}
}

func TestNewPassword(t *testing.T) {
	t.Parallel()
	a, err := setupcode.NewPassword()
	require.NoError(t, err)
	b, err := setupcode.NewPassword()
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	require.Regexp(t, `^[0-9a-f]{64}$`, a, "256 bits, hex")
}
