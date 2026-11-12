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
	require.Equal(t, engine, portal, "web/_headers /* block drifted from internal/websec")
	require.Equal(t, "max-age=31536000; includeSubDomains", hsts)
	require.Equal(t, map[string]string{"Content-Type": "text/javascript"}, rules["/*.js"])
	require.Len(t, rules, 2, "unexpected extra rules in web/_headers")
}

func TestPortalCSPHasNoInlineOrRemoteSources(t *testing.T) {
	t.Parallel()
	csp := parseHeadersFile(t, portalHeadersFile)["/*"]["Content-Security-Policy"]
	require.NotContains(t, csp, "unsafe-inline")
	require.NotContains(t, csp, "unsafe-eval")
	require.NotContains(t, csp, "connect-src", "connect-src falls back to default-src 'self'")
	require.NotRegexp(t, regexp.MustCompile(`https?:|wss?:|\*`), csp)
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
