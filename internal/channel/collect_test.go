package channel

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The collect body is the five lines CONTRACT.md (Connect, The address
// hand-off) pins for the fixtures' setup code, and the shared vector signs
// exactly those bytes.
func TestConnectCollectBody(t *testing.T) {
	t.Parallel()
	body := ConnectCollectBody("01a1f78c-52b8-7c3a-9f00-0000000000e1", "734b aaea 804e 1065 4148", "2026-11-20T06:10:00Z")
	want := "basalt-connect-collect.1\nconnect.basaltvault.app\n01a1f78c-52b8-7c3a-9f00-0000000000e1\n734b aaea 804e 1065 4148\n2026-11-20T06:10:00Z"
	require.Equal(t, want, string(ContextConnectCollect)+string(body))
	found := false
	for _, c := range loadVectors[connectSignatureCase](t, "signature.json", "SIGNATURE") {
		if c.Context != "CONNECT_COLLECT" || c.Expect != "ACCEPT" {
			continue
		}
		require.Equal(t, hex.EncodeToString([]byte(want)), c.Message)
		found = true
	}
	require.True(t, found, "the shared SIGNATURE vectors sign a collect request")
}

// The reach body is the eleven lines CONTRACT.md (Connect, The reach check)
// pins for both of its examples, and the shared vector signs the first.
func TestConnectReachBody(t *testing.T) {
	t.Parallel()
	const id, fp = "01a1f78c-52b8-7c3a-9f00-0000000000e1", "734b aaea 804e 1065 4148"
	body := ConnectReachBody(id, fp, "2026-11-20T06:10:15Z", "aws-0-eu-central-1.pooler.supabase.com", 5432, "postgres", "abcdefghijklmnopqrst", "REACHABLE", "")
	want := "basalt-connect-reach.1\nconnect.basaltvault.app\n" + id + "\n" + fp + "\n2026-11-20T06:10:15Z\n" +
		"aws-0-eu-central-1.pooler.supabase.com\n5432\npostgres\nabcdefghijklmnopqrst\nREACHABLE\n"
	require.Equal(t, want, string(ContextConnectReach)+string(body))
	timeout := ConnectReachBody(id, fp, "2026-11-20T06:10:15Z", "db.example.com", 6543, "app", "", "UNREACHABLE", "TIMEOUT")
	require.True(t, strings.HasSuffix(string(timeout), "\ndb.example.com\n6543\napp\n\nUNREACHABLE\nTIMEOUT"), string(timeout))
	found := false
	for _, c := range loadVectors[connectSignatureCase](t, "signature.json", "SIGNATURE") {
		if c.Context != "CONNECT_REACH" || c.Expect != "ACCEPT" {
			continue
		}
		require.Equal(t, hex.EncodeToString([]byte(want)), c.Message)
		found = true
	}
	require.True(t, found, "the shared SIGNATURE vectors sign a reach report")
}

type connectSignatureCase struct {
	Name      string `json:"name"`
	Context   string `json:"context"`
	PublicKey string `json:"publicKey"`
	Message   string `json:"message"`
	Sig       string `json:"sig"`
	Expect    string `json:"expect"`
}
