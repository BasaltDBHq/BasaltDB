package web_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/web"
)

var connectSrc = regexp.MustCompile(`connect-src ([^;"]+)`)

// The approve, revert and plugin pages of a short link read the request from the
// engine and post the signature back (same origin), so their meta CSP must
// allow connect-src 'self'; a browser blocks the fetch otherwise. On the
// portal the approve and revert pages reach the engine through the Vault
// instead, so theirs adds wss://relay.basaltvault.app and nothing else. So must
// the registration page, which posts the passkey back to basalt init when
// init serves it. The passkey management page never fetches and keeps
// 'none'.
func TestPageCSPConnectSrc(t *testing.T) {
	cases := map[string]string{
		"approve/index.html":  "'self' wss://relay.basaltvault.app",
		"revert/index.html":   "'self' wss://relay.basaltvault.app",
		"plugin/index.html":   "'self'",
		"register/index.html": "'self'",
		// The setup page posts the job to the engine's own setup routes.
		"setup/index.html":    "'self'",
		"passkeys/index.html": "'none'",
		// The pin page reaches only the address it checks, which the
		// portal's edge function adds for that request.
		// The connect page reaches the connect service and nothing else.
		"connect/index.html": "https://connect.basaltvault.app",
	}
	for page, want := range cases {
		t.Run(page, func(t *testing.T) {
			body, err := web.Files.ReadFile(page)
			require.NoError(t, err)
			m := connectSrc.FindSubmatch(body)
			require.NotNil(t, m, "page has no connect-src in its CSP")
			require.Equal(t, want, string(m[1]))
		})
	}
}

// make portal-build (run before the tests in make ci) must publish exactly
// the embedded files plus the Pages config, so a new embedded page cannot be
// missing from the portal and no test or Go file can slip in.
func TestPortalBuildMatchesEmbed(t *testing.T) {
	const dist = "../dist/portal"
	if _, err := os.Stat(dist); err != nil {
		t.Skip("run make portal-build first")
	}
	want := []string{"_headers", "_redirects", "_routes.json"}
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			want = append(want, p)
		}
		return err
	}))
	var got []string
	require.NoError(t, filepath.WalkDir(dist, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, rerr := filepath.Rel(dist, p)
			require.NoError(t, rerr)
			got = append(got, filepath.ToSlash(rel))
		}
		return err
	}))
	require.ElementsMatch(t, want, got)
}

// Signing is "sign with your passkey", never a brand's biometric name, and
// every signing page says the biometrics stay on the device.
func TestSigningPagesSayBiometricsStayOnTheDevice(t *testing.T) {
	const line = "Your fingerprint or face never leaves this device; Basalt only receives a signature."
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (!strings.HasSuffix(p, ".html") && !strings.HasSuffix(p, ".js")) {
			return err
		}
		body, rerr := web.Files.ReadFile(p)
		require.NoError(t, rerr)
		require.NotContains(t, strings.ToLower(string(body)), "touch id", p)
		return nil
	}))
	for _, page := range []string{"approve", "revert", "plugin", "register", "passkeys", "connect", "setup"} {
		body, err := web.Files.ReadFile(page + "/index.html")
		require.NoError(t, err)
		require.Contains(t, string(body), line, page)
	}
}

// web/portal.sha256, the release manifest that
// `basalt portal verify` checks the binary's pages against) lists exactly
// the embedded files with their SHA-256. Run make web-sri after editing web/.
func TestManifestMatchesEmbed(t *testing.T) {
	manifest, err := os.ReadFile("portal.sha256")
	require.NoError(t, err)
	want := map[string]string{}
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := web.Files.ReadFile(p)
		sum := sha256.Sum256(b)
		want[p] = hex.EncodeToString(sum[:])
		return rerr
	}))
	got := map[string]string{}
	lines := strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n")
	order := make([]string, 0, len(lines))
	for _, l := range lines {
		h, p, ok := strings.Cut(l, "  ")
		require.True(t, ok, l)
		got[p] = h
		order = append(order, p)
	}
	require.True(t, sort.StringsAreSorted(order), "manifest is sorted by path")
	require.Equal(t, want, got, "web/portal.sha256 is out of date; run make web-sri")
}
