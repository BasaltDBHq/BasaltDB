package channel

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The collect body is the five lines CONTRACT.md (Connect, The address
// hand-off) pins for the fixtures' setup code, and the shared vector signs
// exactly those bytes.
func TestConnectCollectBody(t *testing.T) {
	t.Parallel()
	body := ConnectCollectBody("01a1f78c-52b8-7c3a-9f00-0000000000e1", "d48b ee66 a1d9 d005 1f63", "2026-11-20T06:10:00Z")
	want := "basalt-connect-collect.1\nconnect.basaltvault.app\n01a1f78c-52b8-7c3a-9f00-0000000000e1\nd48b ee66 a1d9 d005 1f63\n2026-11-20T06:10:00Z"
	require.Equal(t, want, string(ContextConnectCollect)+string(body))
	type signatureCase struct {
		Name      string `json:"name"`
		Context   string `json:"context"`
		PublicKey string `json:"publicKey"`
		Message   string `json:"message"`
		Sig       string `json:"sig"`
		Expect    string `json:"expect"`
	}
	found := false
	for _, c := range loadVectors[signatureCase](t, "signature.json", "SIGNATURE") {
		if c.Context != "CONNECT_COLLECT" || c.Expect != "ACCEPT" {
			continue
		}
		require.Equal(t, hex.EncodeToString([]byte(want)), c.Message)
		found = true
	}
	require.True(t, found, "the shared SIGNATURE vectors sign a collect request")
}
