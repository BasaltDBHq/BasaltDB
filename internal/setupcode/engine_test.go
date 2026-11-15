package setupcode_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
)

// A code may carry the engine's key (M4.1): it round-trips, comes last in
// the payload, and the fingerprint covers it.
func TestEngineInTheCode(t *testing.T) {
	t.Parallel()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	spki := keys.PublicKeySPKI()
	p := validPayload(t)
	without := p
	p.Engine = &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(spki)}

	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	got, err := setupcode.Decode(code)
	require.NoError(t, err)
	require.Equal(t, p, got)
	key, err := got.Engine.Key()
	require.NoError(t, err)
	require.Equal(t, spki, key)
	require.NotEqual(t, without.Fingerprint(), got.Fingerprint(), "the fingerprint covers the engine key")

	// A key that is not one is INVALID.
	compressed := append([]byte{}, spki...)
	compressed[26] = 0x02
	for _, k := range []string{"", "AAAA", base64.RawURLEncoding.EncodeToString(compressed), strings.Repeat("A", 122)} {
		bad := p
		bad.Engine = &setupcode.Engine{PublicKey: k}
		_, err = setupcode.Encode(bad)
		require.Equal(t, setupcode.RefusalInvalid, refusalOf(t, err), k)
	}
}
