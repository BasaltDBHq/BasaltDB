package channel_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/channel/channeltest"
)

// The shared RECEIPT vectors run through the engine's own verifier.
func TestReceiptVectors(t *testing.T) {
	t.Parallel()
	type receiptCase struct {
		Name        string `json:"name"`
		Token       string `json:"token"`
		EngineKey   string `json:"engineKey"`
		PayloadJSON string `json:"payloadJson,omitempty"`
		Expect      string `json:"expect"`
	}
	cases := channel.LoadVectors[receiptCase](t, "receipt.json", "RECEIPT")
	require.NotEmpty(t, cases)
	for _, c := range cases {
		key, err := channel.Unb64(c.EngineKey)
		require.NoError(t, err, c.Name)
		got, err := channeltest.VerifyReceipt(c.Token, key)
		require.Equal(t, c.Expect, channel.Outcome(err), c.Name)
		if err != nil {
			continue
		}
		raw, err := json.Marshal(got)
		require.NoError(t, err)
		require.Equal(t, c.PayloadJSON, string(raw), "the engine writes the vector's exact bytes: %s", c.Name)
	}
}

func testKeys(t *testing.T) *channel.EngineKeys {
	t.Helper()
	k, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	return k
}

func sampleReceipt(k *channel.EngineKeys) channel.Receipt {
	return channel.Receipt{
		Kind: channel.ReceiptApproval, ItemID: "0192f3a0-7c1e-7b2a-9c4d-5e6f708192a3", Status: channel.ReceiptApproved,
		Headline: "Update 3 rows in public.orders", RowsHash: strings.Repeat("ab", 32),
		Agent: "agent:billing_bot", EngineID: k.EngineID(), At: "2026-11-12T09:30:00Z",
	}
}

func TestSignReceiptRoundTrip(t *testing.T) {
	t.Parallel()
	k := testKeys(t)
	r := sampleReceipt(k)
	tok, err := channel.SignReceipt(k, r)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(tok, channel.ReceiptPrefix))
	got, err := channeltest.VerifyReceipt(tok, k.PublicKeySPKI())
	require.NoError(t, err)
	r.Format = 1
	require.Equal(t, r, got)
}

func TestSignReceiptRefusesWhatAVerifierWouldRefuse(t *testing.T) {
	t.Parallel()
	k := testKeys(t)
	other := testKeys(t)
	r := sampleReceipt(k)
	r.EngineID = other.EngineID()
	_, err := channel.SignReceipt(k, r)
	require.Error(t, err, "a receipt names its own signer")
	r = sampleReceipt(k)
	r.Headline = ""
	_, err = channel.SignReceipt(k, r)
	require.Error(t, err)
}

// signRaw signs arbitrary payload bytes with k, as an engine would.
func signRaw(t *testing.T, k *channel.EngineKeys, payload string) string {
	t.Helper()
	sig, err := k.Sign(channel.ContextReceipt, []byte(payload))
	require.NoError(t, err)
	return channel.ReceiptPrefix + channel.B64([]byte(payload)) + "." + channel.B64(sig)
}

func TestVerifyReceiptRefusals(t *testing.T) {
	t.Parallel()
	k := testKeys(t)
	attacker := testKeys(t)
	good, err := channel.SignReceipt(k, sampleReceipt(k))
	require.NoError(t, err)
	payload, err := json.Marshal(func() channel.Receipt { r := sampleReceipt(k); r.Format = 1; return r }())
	require.NoError(t, err)
	body := string(payload)

	// Signed by another key, naming the expected engine.
	forged := signRaw(t, attacker, body)
	_, err = channeltest.VerifyReceipt(forged, k.PublicKeySPKI())
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "signed by another key")
	// Checked only against the key that came with it: the attacker's key
	// verifies the signature, but the payload names another engine.
	_, err = channeltest.VerifyReceipt(forged, attacker.PublicKeySPKI())
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "checked against only the key that came with it")
	// Signed by the expected key, naming another engine.
	other := strings.Replace(body, k.EngineID(), attacker.EngineID(), 1)
	_, err = channeltest.VerifyReceipt(signRaw(t, k, other), k.PublicKeySPKI())
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "engineId is not the expected key's")
	// No expected key at all.
	_, err = channeltest.VerifyReceipt(good, nil)
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "an expected key is required")

	for name, p := range map[string]string{
		"extra field":       strings.TrimSuffix(body, "}") + `,"rows":3}`,
		"key in other case": strings.Replace(body, `"itemId"`, `"ItemId"`, 1),
		"duplicate key":     strings.TrimSuffix(body, "}") + `,"agent":"other-bot"}`,
		"null changeId":     strings.TrimSuffix(body, "}") + `,"changeId":null}`,
		"empty changeId":    strings.TrimSuffix(body, "}") + `,"changeId":""}`,
		"missing rowsHash":  strings.Replace(body, `"rowsHash":"`+strings.Repeat("ab", 32)+`",`, "", 1),
		"format 2":          strings.Replace(body, `"format":1`, `"format":2`, 1),
		"bad status":        strings.Replace(body, `"APPROVED"`, `"PENDING"`, 1),
		"trailing data":     body + " {}",
		"at with offset":    strings.Replace(body, `09:30:00Z`, `11:30:00+02:00`, 1),
	} {
		require.NotEqual(t, body, p, name)
		_, err := channeltest.VerifyReceipt(signRaw(t, k, p), k.PublicKeySPKI())
		require.ErrorIs(t, err, channeltest.ErrBadReceipt, name)
	}

	// A bad signature.
	parts := strings.Split(strings.TrimPrefix(good, channel.ReceiptPrefix), ".")
	sig, err := channel.Unb64(parts[1])
	require.NoError(t, err)
	sig[3] ^= 1
	_, err = channeltest.VerifyReceipt(channel.ReceiptPrefix+parts[0]+"."+channel.B64(sig), k.PublicKeySPKI())
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "bad signature")
	// A signature under another context.
	sessionSig, err := k.Sign(channel.ContextSession, payload)
	require.NoError(t, err)
	_, err = channeltest.VerifyReceipt(channel.ReceiptPrefix+parts[0]+"."+channel.B64(sessionSig), k.PublicKeySPKI())
	require.ErrorIs(t, err, channeltest.ErrBadReceipt, "another signing context")
}
