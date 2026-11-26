package setup_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// The engine's own address policy: private, reserved and documentation
// ranges are refused, public unicast is allowed.
func TestAddressAllowed(t *testing.T) {
	t.Parallel()
	for addr, want := range map[string]bool{
		"8.8.8.8":           true,
		"2606:4700::1111":   true,
		"10.0.0.1":          false,
		"127.0.0.1":         false,
		"169.254.169.254":   false,
		"100.64.0.1":        false,
		"203.0.113.9":       false,
		"::1":               false,
		"::ffff:8.8.8.8":    false,
		"2001:db8::1":       false,
		"fd00::1":           false,
		"4000::1":           false,
		"fe80::1%eth0":      false,
		"255.255.255.255":   false,
		"64:ff9b::808:808":  false,
		"2002:808:808::1":   false,
		"3fff::1":           false,
		"192.88.99.1":       false,
		"198.18.0.1":        false,
		"100::1":            false,
		"5f00::1":           false,
		"fec0::1":           false,
		"ff02::1":           false,
		"224.0.0.1":         false,
		"0.0.0.1":           false,
		"192.0.0.1":         false,
		"198.51.100.1":      false,
		"64:ff9b:1::1":      false,
		"::ffff:0:808:808":  false,
		"2001:0:4136::1":    false,
		"192.168.1.1":       false,
		"172.16.0.1":        false,
		"240.0.0.1":         false,
		"192.0.2.1":         false,
		"2001:4860::8888":   true,
		"1.1.1.1":           true,
		"2a00:1450:4001::1": true,
	} {
		require.Equal(t, want, setup.AddressAllowed(netip.MustParseAddr(addr)), addr)
	}
	require.False(t, setup.AddressAllowed(netip.Addr{}))
}

// The refused list is the contract's 30 ranges, and a caller gets a copy.
func TestRefusedPrefixes(t *testing.T) {
	t.Parallel()
	got := setup.RefusedPrefixes()
	require.Len(t, got, 30)
	for _, p := range got {
		require.False(t, setup.AddressAllowed(p.Addr()), p.String())
	}
	got[0] = netip.MustParsePrefix("8.8.8.0/24")
	require.NotEqual(t, got[0], setup.RefusedPrefixes()[0])
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

var _ setup.Resolver = setup.SystemResolver{}

// PickAddress resolves once, refuses a name with any refused address, and
// prefers IPv4.
func TestPickAddress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := fakeResolver{
		"dual.example.com":     {netip.MustParseAddr("2606:4700::1111"), netip.MustParseAddr("1.1.1.1")},
		"mixed.example.com":    {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")},
		"v6only.example.com":   {netip.MustParseAddr("2606:4700::1111")},
		"metadata.example.com": {netip.MustParseAddr("169.254.169.254")},
	}
	a, err := setup.PickAddress(ctx, r, "dual.example.com")
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1", a.String())
	a, err = setup.PickAddress(ctx, r, "v6only.example.com")
	require.NoError(t, err)
	require.Equal(t, "2606:4700::1111", a.String())
	a, err = setup.PickAddress(ctx, r, "8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8", a.String())
	for _, host := range []string{"mixed.example.com", "metadata.example.com", "10.0.0.1"} {
		_, err = setup.PickAddress(ctx, r, host)
		require.Error(t, err, host)
		require.True(t, setup.AddressRefused(err), host)
	}
	_, err = setup.PickAddress(ctx, r, "nowhere.example.com")
	require.Error(t, err)
	require.False(t, setup.AddressRefused(err))
}

// The contract's example check code: the P-256 base point.
func TestCheckCode(t *testing.T) {
	t.Parallel()
	p := elliptic.P256().Params()
	require.Equal(t, "dbf5 ff76 2025 209d d866", setup.CheckCode(p.Gx.FillBytes(make([]byte, 32)), p.Gy.FillBytes(make([]byte, 32))))
	require.Equal(t, "basalt-passkey.1.", setup.PasskeyRegistrationPrefix)
}

// The Supabase ref is the engine's: the direct host db.<ref>.supabase.co, or
// the text after the first dot of a pooler user, and only a 20-character
// lowercase ref.
func TestSupabaseRef(t *testing.T) {
	t.Parallel()
	const ref = "abcdefghijklmnopqrst"
	for _, c := range []struct{ host, user, want string }{
		{"db." + ref + ".supabase.co", "postgres", ref},
		{"DB." + strings.ToUpper(ref) + ".SUPABASE.CO", "postgres", ref},
		{"aws-0-eu-central-1.pooler.supabase.com", "postgres." + ref, ref},
		{"aws-0-eu-central-1.pooler.supabase.com", "a.b." + ref, ""},
		{"aws-0-eu-central-1.pooler.supabase.com", "postgres." + strings.ToUpper(ref), ""},
		{"aws-0-eu-central-1.pooler.supabase.com", "postgres", ""},
		{"db.short.supabase.co", "postgres", ""},
		{"db.example.com", "postgres." + ref, ""},
	} {
		require.Equal(t, c.want, setup.SupabaseRef(c.host, c.user), "%s %s", c.host, c.user)
	}
}

// Canonical lowercases the host and the ref, and nothing else.
func TestTargetCanonical(t *testing.T) {
	t.Parallel()
	got := setup.Target{Host: "DB.Example.COM.", Port: 6543, Database: "MyDB", SupabaseRef: "ABC"}.Canonical()
	require.Equal(t, setup.Target{Host: "db.example.com.", Port: 6543, Database: "MyDB", SupabaseRef: "abc"}, got)
}

// The connect signed texts and their checks agree with the engine's shared
// vectors: a valid vector is rebuilt byte for byte from its fields and
// verifies; every other vector is refused.
func TestConnectSignatureVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "api", "mcp", "vault", "testdata", "signature.json"))
	require.NoError(t, err)
	var file struct {
		Cases []struct {
			Name, Context, PublicKey, Message, Sig, Expect string
		}
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	b64 := base64.RawURLEncoding
	seen := map[string]bool{}
	for _, c := range file.Cases {
		var context string
		switch c.Context {
		case "CONNECT_COLLECT":
			context = setup.ConnectCollectContext
		case "CONNECT_REACH":
			context = setup.ConnectReachContext
		default:
			continue
		}
		message, err := hex.DecodeString(c.Message)
		require.NoError(t, err, c.Name)
		key, keyErr := b64.DecodeString(c.PublicKey)
		sig, sigErr := b64.DecodeString(c.Sig)
		body, ok := bytes.CutPrefix(message, []byte(context))
		lines := strings.Split(string(body), "\n")
		var verr error
		switch {
		case keyErr != nil || sigErr != nil || !ok:
			verr = errors.New("not this context")
		case c.Context == "CONNECT_COLLECT" && len(lines) == 4:
			require.Equal(t, message, append([]byte(context), setup.ConnectCollectBody(lines[1], lines[2], lines[3])...), c.Name)
			verr = setup.VerifyConnectCollect(key, sig, lines[1], lines[2], lines[3])
		case c.Context == "CONNECT_REACH" && len(lines) == 10:
			port, err := strconv.Atoi(lines[5])
			require.NoError(t, err, c.Name)
			a := setup.Target{Host: lines[4], Port: port, Database: lines[6], SupabaseRef: lines[7]}
			require.Equal(t, message, append([]byte(context), setup.ConnectReachBody(lines[1], lines[2], lines[3], a, lines[8], lines[9])...), c.Name)
			verr = setup.VerifyConnectReach(key, sig, lines[1], lines[2], lines[3], a, lines[8], lines[9])
		default:
			verr = errors.New("not this text's shape")
		}
		want := c.Expect == "ACCEPT"
		require.Equal(t, want, verr == nil, "%s: %v", c.Name, verr)
		if want {
			require.Equal(t, setup.ConnectAudience, lines[0], c.Name)
			seen[c.Context] = true
		}
	}
	require.Len(t, seen, 2, "a valid vector for each connect context")
}
