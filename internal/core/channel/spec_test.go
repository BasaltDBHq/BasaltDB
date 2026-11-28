package channel

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const specPath = "../../../docs/security/vault-channel-spec.md"

// specBlock returns the lines of the fenced block opened by "```constants <name>"
// in the outside-reviewer spec.
func specBlock(t *testing.T, doc, name string) []string {
	t.Helper()
	open := "```constants " + name + "\n"
	_, rest, ok := strings.Cut(doc, open)
	require.True(t, ok, "the spec has no %q block", open)
	body, _, ok := strings.Cut(rest, "```")
	require.True(t, ok, "the %q block is not closed", name)
	return strings.Split(strings.TrimSpace(body), "\n")
}

// specKeyValues parses "key = value" lines and refuses a repeated key.
func specKeyValues(t *testing.T, lines []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, " = ")
		require.True(t, ok, "not a key = value line: %q", l)
		_, dup := out[k]
		require.False(t, dup, "key %q is given twice", k)
		out[k] = v
	}
	return out
}

// unescapeNL turns the spec's written \n into a newline.
func unescapeNL(s string) string { return strings.ReplaceAll(s, `\n`, "\n") }

func specInt(t *testing.T, v string) int {
	t.Helper()
	n, err := strconv.Atoi(v)
	require.NoError(t, err, v)
	return n
}

func specByte(t *testing.T, v string) byte {
	t.Helper()
	n, err := strconv.ParseUint(v, 0, 8)
	require.NoError(t, err, v)
	return byte(n)
}

// TestChannelSpecMatchesContract checks the constants the outside-reviewer
// spec quotes (docs/security/vault-channel-spec.md) against the code, in both
// directions: every line of its constants blocks is checked, and every
// checked name is in the spec.
func TestChannelSpecMatchesContract(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err)
	doc := string(raw)
	kv := specKeyValues(t, specBlock(t, doc, "channel"))
	checked := map[string]bool{}
	get := func(key string) string {
		t.Helper()
		v, ok := kv[key]
		require.True(t, ok, "the spec's constants block has no %q", key)
		checked[key] = true
		return v
	}

	// Protocol name and prologue.
	require.Equal(t, noiseProtocolName, get("protocol-name"))
	require.Len(t, noiseProtocolName, 31, "h starts as the name padded with one zero byte")
	token := LinkToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	template := strings.NewReplacer("<transport>", get("transport-word"), "<linkToken base64url>", token.Wire()).Replace(unescapeNL(get("prologue")))
	require.Equal(t, string(prologue(TransportRelay, token)), template)
	require.Equal(t, string(TransportRelay), get("transport-word"))

	// Version and message types.
	require.Equal(t, wireVersion, specByte(t, get("version-byte")))
	require.Equal(t, typeHello, specByte(t, get("type-hello")))
	require.Equal(t, typeWelcome, specByte(t, get("type-welcome")))
	require.Equal(t, typeFrame, specByte(t, get("type-frame")))

	// Lengths.
	require.Equal(t, Message1Len, specInt(t, get("message-1-length")))
	require.Equal(t, Message2Max, specInt(t, get("message-2-max")))
	require.Equal(t, PointLen, specInt(t, get("point-length")))
	require.Equal(t, SPKILen, specInt(t, get("spki-length")))
	require.Equal(t, SigLen, specInt(t, get("signature-length")))
	require.Equal(t, LinkTokenLen, specInt(t, get("link-token-length")))
	require.Equal(t, PSKLen, specInt(t, get("psk-length")))
	require.Equal(t, SecretLen, specInt(t, get("secret-length")))
	spki := spkiOfPoint(make([]byte, PointLen))
	idRaw, err := Unb64(EngineIDOf(spki))
	require.NoError(t, err)
	require.Equal(t, len(idRaw), specInt(t, get("engine-id-bytes")))
	require.Equal(t, len(strings.ReplaceAll(FingerprintOf(EngineIDOf(spki)), " ", "")), specInt(t, get("fingerprint-chars")))

	// HKDF info strings, through the derivation itself.
	secret := b64([]byte("0123456789abcdef"))
	lk, err := DeriveLink(secret)
	require.NoError(t, err)
	ikm := []byte("0123456789abcdef")
	wantToken, err := hkdf.Key(sha256.New, ikm, nil, get("hkdf-info-link-token"), LinkTokenLen)
	require.NoError(t, err)
	wantPSK, err := hkdf.Key(sha256.New, ikm, nil, get("hkdf-info-psk"), PSKLen)
	require.NoError(t, err)
	require.Equal(t, wantToken, lk.Token[:])
	require.Equal(t, wantPSK, lk.PSK[:])

	// Signing contexts: all of them, and no other.
	contexts := map[string]SigningContext{
		"context-vault-auth": ContextVaultAuth, "context-session": ContextSession, "context-receipt": ContextReceipt,
		"context-box-key": ContextBoxKey, "context-rotate": ContextRotate,
		"context-connect-collect": ContextConnectCollect, "context-connect-reach": ContextConnectReach,
		"context-connect-removed": ContextConnectRemoved,
	}
	for key, want := range contexts {
		require.Equal(t, string(want), unescapeNL(get(key)), key)
		require.True(t, want.valid(), key)
		require.Contains(t, doc, "`"+strings.ReplaceAll(string(want), "\n", `\n`)+"`", "the contexts table names %s", key)
	}

	// Padding bounds.
	require.Equal(t, padMin, specInt(t, get("padding-min")))
	require.Equal(t, padMax, specInt(t, get("padding-max")))
	require.Equal(t, lenPrefix, specInt(t, get("padding-length-prefix")))
	require.Equal(t, ContentMax, specInt(t, get("content-max")))
	require.Equal(t, FrameMax, specInt(t, get("frame-max")))
	require.Equal(t, padMin, bucket(0))
	require.Equal(t, padMax, bucket(ContentMax))

	// Nonce rule: 4 zero bytes, then the counter, big-endian.
	require.Equal(t, "4 zero bytes, then the counter as 8 bytes big-endian", get("nonce"))
	m := regexp.MustCompile(`^counter (0x[0-9a-f]+) gives ([0-9a-f]+)$`).FindStringSubmatch(get("nonce-example"))
	require.NotNil(t, m, "nonce-example")
	counter, err := strconv.ParseUint(m[1], 0, 64)
	require.NoError(t, err)
	require.Equal(t, m[2], hex.EncodeToString(noiseNonce(counter)))

	// Every line of the block was checked.
	for key := range kv {
		require.True(t, checked[key], "the spec's constants block has a line nothing checks: %q", key)
	}

	// Close codes: the same set as the registry, no more and no fewer.
	codes := make(map[CloseError]string, len(closeNames))
	for _, l := range specBlock(t, doc, "close-codes") {
		var code int
		var name string
		_, err := fmt.Sscanf(l, "%d %s", &code, &name)
		require.NoError(t, err, l)
		codes[CloseError(code)] = name
	}
	require.Equal(t, closeNames, codes)
	for code, name := range codes {
		require.Contains(t, doc, fmt.Sprintf("| %d | %#q |", code, name), "the close-code table names %s", name)
	}
}

// TestChannelSpecNamesEveryVectorFile checks that each shared vector file is
// named in the spec with its case count, and that the pages link to the spec.
func TestChannelSpecNamesEveryVectorFile(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err)
	doc := string(raw)
	files, err := filepath.Glob("../../../api/mcp/vault/testdata/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		name := filepath.Base(f)
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		cases := strings.Count(string(data), "\n      \"name\":")
		row := regexp.MustCompile("`api/mcp/vault/testdata/" + regexp.QuoteMeta(name) + `.*\((\d+) cases\)`).FindStringSubmatch(doc)
		require.NotNil(t, row, "the spec does not name %s with its case count", name)
		require.Equal(t, strconv.Itoa(cases), row[1], "the case count of %s", name)
	}
	for _, page := range []string{"../../../SECURITY.md", "../../../docs/vault.md"} {
		text, err := os.ReadFile(page)
		require.NoError(t, err)
		require.Contains(t, string(text), "vault-channel-spec.md", page)
	}
}
