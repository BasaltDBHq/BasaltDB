package websec_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/websec"
)

const portalHeadersFile = "../../web/_headers"

// parseHeadersFile reads a Cloudflare Pages _headers file into rule -> header -> value.
func parseHeadersFile(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	require.NoError(t, err)
	defer f.Close()

	rules := map[string]map[string]string{}
	current := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			current = trimmed
			rules[current] = map[string]string{}
			continue
		}
		require.NotEmpty(t, current, "header line before any path: %q", line)
		name, value, ok := strings.Cut(trimmed, ":")
		require.True(t, ok, "bad header line: %q", line)
		rules[current][strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	require.NoError(t, sc.Err())
	return rules
}

func TestPortalHeadersMatchEngine(t *testing.T) {
	t.Parallel()
	rules := parseHeadersFile(t, portalHeadersFile)

	rec := httptest.NewRecorder()
	websec.Headers()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	// Every header the engine sets, so a new one cannot be added to one side only.
	engine := map[string]string{}
	for name := range rec.Header() {
		engine[name] = rec.Header().Get(name)
	}
	require.NotEmpty(t, engine)

	// HSTS is portal-only: browsers ignore it on the engine's http loopback.
	portal := map[string]string{}
	for name, value := range rules["/*"] {
		portal[name] = value
	}
	hsts := portal["Strict-Transport-Security"]
	delete(portal, "Strict-Transport-Security")
	// The CSP is the engine's with the portal's connect-src, the Vault.
	require.Equal(t, websec.PortalCSP, portal["Content-Security-Policy"], "web/_headers CSP drifted from websec.PortalCSP")
	engine["Content-Security-Policy"] = websec.PortalCSP
	require.Equal(t, engine, portal, "web/_headers /* block drifted from internal/websec")
	for name, values := range websec.ExpectedPortal() {
		require.Equal(t, values[0], portal[name], name)
	}
	require.Equal(t, "max-age=31536000; includeSubDomains", hsts)
	require.Equal(t, map[string]string{"Content-Type": "text/javascript"}, rules["/*.js"])
	require.Len(t, rules, 2, "unexpected extra rules in web/_headers")
}

// The connect page's policy is the pages' policy with one connect-src, the
// connect service, and the portal's edge function serves exactly it.
func TestConnectPageCSPMatchesEdgeFunction(t *testing.T) {
	t.Parallel()
	edge, err := os.ReadFile(filepath.Clean("../../web/edge/portal.js"))
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^export const CONNECT_CSP = "([^"]*)";$`).FindSubmatch(edge)
	require.NotNil(t, m, "web/edge/portal.js has no CONNECT_CSP")
	require.Equal(t, websec.ConnectPageCSP, string(m[1]))

	def := websec.Expected().Get("Content-Security-Policy")
	require.Equal(t, strings.Replace(def, "default-src 'self'; ", "default-src 'self'; connect-src https://connect.basaltvault.app; ", 1), websec.ConnectPageCSP)

	h := websec.ExpectedConnectPage()
	require.Equal(t, websec.ConnectPageCSP, h.Get("Content-Security-Policy"))
	require.Equal(t, "no-store", h.Get("Cache-Control"))
	for name := range websec.Expected() {
		if name != "Content-Security-Policy" {
			require.Equal(t, websec.Expected().Get(name), h.Get(name), name)
		}
	}
}

func TestPortalCSPHasNoInlineOrRemoteSources(t *testing.T) {
	t.Parallel()
	csp := parseHeadersFile(t, portalHeadersFile)["/*"]["Content-Security-Policy"]
	require.NotContains(t, csp, "unsafe-inline")
	require.NotContains(t, csp, "unsafe-eval")
	// connect-src names the Vault and nothing else: no scheme, no wildcard,
	// no other host, not even 'self'.
	m := regexp.MustCompile(`(?:^|; )connect-src ([^;]*)(?:;|$)`).FindAllStringSubmatch(csp, -1)
	require.Len(t, m, 1, "one connect-src")
	require.Equal(t, "wss://relay.basaltvault.app", m[0][1])
	require.NotRegexp(t, regexp.MustCompile(`https?:|\*`), csp)
	require.Equal(t, 1, strings.Count(csp, "wss:"), "the Vault is the only remote source")
}

// The engine's own pages fetch their own origin and never open the Vault:
// their policy has no connect-src (it falls back to default-src 'self').
func TestEngineCSPHasNoConnectSrc(t *testing.T) {
	t.Parallel()
	csp := websec.Expected().Get("Content-Security-Policy")
	require.NotContains(t, csp, "connect-src")
	require.NotRegexp(t, regexp.MustCompile(`https?:|wss?:|\*`), csp)
	require.Equal(t, strings.Replace(csp, "default-src 'self'; ", "default-src 'self'; connect-src wss://relay.basaltvault.app; ", 1), websec.PortalCSP)
}

func TestPortalPagesHaveNoInlineScriptsOrHandlers(t *testing.T) {
	t.Parallel()
	pages, err := filepath.Glob("../../web/*/index.html")
	require.NoError(t, err)
	require.NotEmpty(t, pages)
	scriptTag := regexp.MustCompile(`(?is)<script\b[^>]*>`)
	inline := regexp.MustCompile(`(?i)\son[a-z]+\s*=|javascript:|\sstyle\s*=|<style`)
	for _, p := range pages {
		b, err := os.ReadFile(filepath.Clean(p))
		require.NoError(t, err)
		page := string(b)
		for _, tag := range scriptTag.FindAllString(page, -1) {
			require.Contains(t, tag, "src=", "%s: inline script %s", p, tag)
		}
		require.NotRegexp(t, inline, page, p)
	}
}
