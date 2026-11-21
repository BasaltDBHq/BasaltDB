package providerca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pinnedFiles are the SHA-256 of each embedded file as its provider
// publishes it, and its certificate count, pinned here apart from the
// provider table: a changed file, or a changed pin in the table, fails a
// test. make check-provider-roots compares the published files with the
// table.
var pinnedFiles = map[string]struct {
	provider string
	sha256   string
	certs    int
}{
	"supabase-root-2021.crt": {Supabase, "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7", 1},
	"supabase-root-2025.crt": {Supabase, "5865d2b26f6128e5795a13ae58b6543599bdb82d808f7f62e3c9a8d7e8527970", 1},
	"rds-global-bundle.pem":  {RDS, "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b", 114},
}

// supabaseRootSHA256 are the SHA-256 fingerprints of the DER of Supabase's
// two roots, as Supabase publishes them. Both are named Supabase Root 2021
// CA; the 2025 one has a new key.
var supabaseRootSHA256 = []string{
	"80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA",
	"5F:9B:77:95:1A:7A:A1:30:3F:9B:58:EE:A9:BF:A8:9E:35:8C:FD:C1:5F:97:86:FF:10:D4:93:0A:72:2C:9A:E2",
}

// Every embedded file is in the table once, matches its pin on disk and in
// the table, and holds only CA certificates, all of them in its provider's
// roots and none in another's.
func TestProviderFilesPinned(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, p := range providers {
		total := 0
		for _, f := range p.files {
			want, ok := pinnedFiles[f.path]
			require.True(t, ok, "%s is not pinned", f.path)
			require.False(t, seen[f.path], "%s is in the table twice", f.path)
			seen[f.path] = true
			require.Equal(t, want.provider, p.name, f.path)
			require.Equal(t, want.sha256, f.sha256, "the table's pin of %s", f.path)

			disk, err := os.ReadFile(f.path)
			require.NoError(t, err)
			require.Equal(t, disk, f.pem, "%s is embedded as it is on disk", f.path)
			sum := sha256.Sum256(f.pem)
			require.Equal(t, want.sha256, hex.EncodeToString(sum[:]), f.path)

			certs := mustParse(f.path, f.pem)
			require.Len(t, certs, want.certs, f.path)
			for _, c := range certs {
				require.True(t, c.IsCA, "%s: %s", f.path, c.Subject)
				require.NoError(t, c.CheckSignatureFrom(c), "%s: %s is self-signed", f.path, c.Subject)
			}
			total += len(certs)
		}
		require.Len(t, Roots(p.name), total, p.name)
	}
	require.Len(t, seen, len(pinnedFiles), "every pinned file is in the table")
	require.Nil(t, Roots("neon"))
}

func TestSupabaseRootsAreSupabases(t *testing.T) {
	t.Parallel()
	roots := Roots(Supabase)
	require.Len(t, roots, len(supabaseRootSHA256))
	for i, want := range supabaseRootSHA256 {
		sum := sha256.Sum256(roots[i].Raw)
		require.Equal(t, want, strings.ToUpper(colons(hex.EncodeToString(sum[:]))))
		require.Equal(t, "Supabase Root 2021 CA", roots[i].Subject.CommonName)
	}
	roots[0] = nil
	require.NotNil(t, Roots(Supabase)[0], "Roots returns a copy")
}

func colons(h string) string {
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Each provider's production pool verifies every one of its own roots and
// none of another provider's.
func TestProductionPoolsAreSeparate(t *testing.T) {
	t.Parallel()
	for _, p := range providers {
		pool := p.pool()
		for _, q := range providers {
			for _, root := range q.roots() {
				_, err := root.Verify(x509.VerifyOptions{Roots: pool})
				if q.name == p.name {
					require.NoError(t, err, "%s pool, %s root %s", p.name, q.name, root.Subject)
				} else {
					require.Error(t, err, "%s pool, %s root %s", p.name, q.name, root.Subject)
				}
			}
		}
	}
}

// A file that is not only PEM certificates is a broken build.
func TestMustParseRefusesOtherFiles(t *testing.T) {
	t.Parallel()
	good := supabaseRoot2021PEM
	for name, b := range map[string][]byte{
		"empty":       nil,
		"not PEM":     []byte("hello"),
		"a key block": []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
		"bad DER":     []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"trailing":    append(append([]byte{}, good...), "junk\n"...),
	} {
		require.Panics(t, func() { mustParse(name, b) }, name)
	}
	require.Len(t, mustParse("two", append(append([]byte{}, good...), supabaseRoot2025PEM...)), 2)
}

// pemInCode is the PEM text inside a source file that holds certificates,
// from the first BEGIN line to the end of the last END line and a newline,
// or nil when there is none. make check-provider-roots compares it with the
// embedded file.
func pemInCode(body []byte) []byte {
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	s := string(body)
	i, j := strings.Index(s, begin), strings.LastIndex(s, end)
	if i < 0 || j < i {
		return nil
	}
	return []byte(s[i:j+len(end)] + "\n")
}

// The check takes every certificate in a source file, so a root added next
// to the embedded one changes what it compares, and a file with none gives
// nothing.
func TestPEMInCode(t *testing.T) {
	t.Parallel()
	a, b := supabaseRoot2021PEM, supabaseRoot2025PEM
	module := func(pems ...[]byte) []byte {
		return []byte("export default `" + string(bytes.Join(pems, nil)) + "`;\n")
	}
	require.Equal(t, a, pemInCode(module(a)))
	require.Equal(t, append(append([]byte{}, a...), b...), pemInCode(module(a, b)))
	require.Nil(t, pemInCode([]byte("export default ``;\n")))
}
