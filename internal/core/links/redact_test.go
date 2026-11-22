package links_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// TestSlogNeverPrintsAKeyOrAToken logs every value that holds a link's psk
// or Vault token through slog's text and JSON handlers, and through fmt,
// and checks no form of the bytes shows: base64url, hex, or the byte list a
// JSON handler makes of an array.
func TestSlogNeverPrintsAKeyOrAToken(t *testing.T) {
	t.Parallel()
	var token, oldToken channel.LinkToken
	var psk channel.PSK
	for i := range token {
		token[i], oldToken[i] = 0xAB, 0xCD
	}
	for i := range psk {
		psk[i] = 0xEF
	}
	keys := channel.LinkKeys{Token: token, PSK: psk}
	item := uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000d4")
	expires := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	values := map[string]any{
		"psk":               psk,
		"token":             token,
		"linkKeys":          keys,
		"links.SessionLink": links.SessionLink{Item: item, Keys: keys, ExpiresAt: expires},
		"vault.SessionLink": vault.SessionLink{Token: token, Item: item, PSK: psk, ExpiresAt: expires},
		"rotated":           links.Rotated{Relay: true, Token: token, OldToken: oldToken},
	}
	secrets := [][]byte{token[:], oldToken[:], psk[:]}
	// Per secret: the byte lists slog's JSON and fmt make of an array, then
	// its base64url, base64 and hex forms.
	const formsPerSecret = 6
	forbidden := make([]string, 0, formsPerSecret*len(secrets))
	for _, s := range secrets {
		n := strconv.Itoa(int(s[0]))
		forbidden = append(forbidden, n+","+n, n+" "+n, base64.RawURLEncoding.EncodeToString(s),
			base64.StdEncoding.EncodeToString(s), hex.EncodeToString(s), strings.ToUpper(hex.EncodeToString(s)))
	}
	for name, v := range values {
		var out bytes.Buffer
		slog.New(slog.NewTextHandler(&out, nil)).Info("m", "v", v)
		slog.New(slog.NewJSONHandler(&out, nil)).Info("m", "v", v)
		slog.New(slog.NewJSONHandler(&out, nil)).Info("m", slog.Any("nested", map[string]any{"v": v}))
		fmt.Fprintf(&out, "%v %+v %#v %s\n", v, v, v, v)
		fmt.Fprintf(&out, "%v\n", fmt.Errorf("wrapped: %v", v))
		fmt.Fprintf(&out, "%#v\n", v)
		for _, f := range forbidden {
			require.NotContains(t, out.String(), f, "%s: %s", name, out.String())
		}
	}
	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("m", "v", values["links.SessionLink"], "r", values["rotated"])
	require.Contains(t, out.String(), item.String(), "the item stays")
	require.Contains(t, out.String(), `"relay":true`)
}
