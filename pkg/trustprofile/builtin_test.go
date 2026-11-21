package trustprofile

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pinnedFiles are the SHA-256 of each built-in roots file as its provider
// publishes it, and its certificate count, pinned here apart from the
// profiles: a changed file, or a changed pin in a profile, fails a test.
// make check-provider-roots compares the published files with the profiles.
var pinnedFiles = map[string]struct {
	profile string
	sha256  string
	certs   int
}{
	"supabase-2021.pem":         {"supabase", "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7", 1},
	"supabase-2025.pem":         {"supabase", "5865d2b26f6128e5795a13ae58b6543599bdb82d808f7f62e3c9a8d7e8527970", 1},
	"aws-rds-global-bundle.pem": {"aws-rds", "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b", 114},
}

// supabaseRootFingerprints are the SHA-256 fingerprints of the DER of
// Supabase's two roots, as Supabase publishes them. Both are named Supabase
// Root 2021 CA; the 2025 one has a new key.
var supabaseRootFingerprints = []string{
	"80:70:25:AD:50:D4:ED:21:9D:2C:9C:7D:29:9C:00:4F:82:4E:B0:0C:F7:F6:5A:FE:F6:07:D0:7B:72:E6:CA:FA",
	"5F:9B:77:95:1A:7A:A1:30:3F:9B:58:EE:A9:BF:A8:9E:35:8C:FD:C1:5F:97:86:FF:10:D4:93:0A:72:2C:9A:E2",
}

func builtin(t *testing.T, name string) *Profile {
	t.Helper()
	for _, p := range BuiltIns() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no built-in profile %s", name)
	return nil
}

// The built-in profiles are exactly supabase and aws-rds, each with its
// hosts and a source per file; every file in the directory is a profile
// or one of their roots files, matches its pin on disk and in the profile,
// and holds only self-signed CA certificates.
func TestBuiltInProfilesPinned(t *testing.T) {
	t.Parallel()
	names := make([]string, 0, len(BuiltIns()))
	for _, p := range BuiltIns() {
		names = append(names, p.Name)
		require.Equal(t, BuiltIn, p.Origin)
		require.Len(t, p.Source, len(p.Roots), "%s: one source per roots file", p.Name)
		for _, f := range p.Files {
			want, ok := pinnedFiles[f.Name]
			require.True(t, ok, "%s is not pinned", f.Name)
			require.Equal(t, want.profile, p.Name, f.Name)
			require.Equal(t, want.sha256, f.SHA256, f.Name)
			disk, err := os.ReadFile(filepath.Join(builtinDir, f.Name))
			require.NoError(t, err)
			require.Equal(t, disk, f.PEM, "%s is embedded as it is on disk", f.Name)
			require.Equal(t, want.sha256, FileSHA256(disk), f.Name)
			require.Len(t, f.Certs, want.certs, f.Name)
			for _, c := range f.Certs {
				require.True(t, c.IsCA, "%s: %s", f.Name, c.Subject)
				require.NoError(t, c.CheckSignatureFrom(c), "%s: %s is self-signed", f.Name, c.Subject)
			}
		}
	}
	require.Equal(t, []string{"aws-rds", "supabase"}, names)
	require.Equal(t, []string{"supabase.co", "supabase.com"}, builtin(t, "supabase").Match)
	require.Equal(t, []string{"rds.amazonaws.com", "rds.amazonaws.com.cn"}, builtin(t, "aws-rds").Match)

	entries, err := os.ReadDir(builtinDir)
	require.NoError(t, err)
	require.Len(t, entries, len(pinnedFiles)+len(names), "the directory holds only the profiles and their roots files")
}

func TestSupabaseRootsAreSupabases(t *testing.T) {
	t.Parallel()
	roots := builtin(t, "supabase").Certificates()
	require.Len(t, roots, len(supabaseRootFingerprints))
	for i, want := range supabaseRootFingerprints {
		require.Equal(t, want, Fingerprint(roots[i]))
		require.Equal(t, "Supabase Root 2021 CA", roots[i].Subject.CommonName)
	}
}

// Each built-in profile's pool verifies every one of its own roots and
// none of another profile's.
func TestBuiltInPoolsAreSeparate(t *testing.T) {
	t.Parallel()
	for _, p := range BuiltIns() {
		for _, q := range BuiltIns() {
			for _, root := range q.Certificates() {
				_, err := root.Verify(x509.VerifyOptions{Roots: p.Pool()})
				if q.Name == p.Name {
					require.NoError(t, err, "%s pool, %s root %s", p.Name, q.Name, root.Subject)
				} else {
					require.Error(t, err, "%s pool, %s root %s", p.Name, q.Name, root.Subject)
				}
			}
		}
	}
}

// pemInCode is the PEM text inside a source file that holds certificates,
// from the first BEGIN line to the end of the last END line and a newline,
// or nil when there is none. make check-provider-roots compares it with the
// embedded file when the source is not itself a PEM file.
func pemInCode(body []byte) []byte {
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	s := string(body)
	i, j := strings.Index(s, begin), strings.LastIndex(s, end)
	if i < 0 || j < i {
		return nil
	}
	return []byte(s[i:j+len(end)] + "\n")
}

// published is what a source serves, as check-provider-roots compares it:
// a PEM file as it is, source code by the PEM text inside it.
func published(body []byte) []byte {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN ")) {
		return body
	}
	return pemInCode(body)
}

// The check takes every certificate in a source file, so a root added next
// to the embedded one changes what it compares, and a file with none gives
// nothing. A PEM file is compared as it is.
func TestPublished(t *testing.T) {
	t.Parallel()
	a := builtin(t, "supabase").Files[0].PEM
	b := builtin(t, "supabase").Files[1].PEM
	module := func(pems ...[]byte) []byte {
		return []byte("export default `" + string(bytes.Join(pems, nil)) + "`;\n")
	}
	require.Equal(t, a, published(module(a)))
	require.Equal(t, append(append([]byte{}, a...), b...), published(module(a, b)))
	require.Nil(t, published([]byte("export default ``;\n")))
	withTrailer := append(append([]byte{}, a...), '\n')
	require.Equal(t, withTrailer, published(withTrailer), "a PEM file is compared byte for byte")
}
