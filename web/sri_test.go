package web_test

import (
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	scriptTag   = regexp.MustCompile(`(?is)<script\b[^>]*>`)
	preloadTag  = regexp.MustCompile(`(?is)<link\b[^>]*\brel="modulepreload"[^>]*>`)
	attrSrc     = regexp.MustCompile(`\bsrc="([^"]+)"`)
	attrHref    = regexp.MustCompile(`\bhref="([^"]+)"`)
	attrIntegr  = regexp.MustCompile(`\bintegrity="(sha384-[A-Za-z0-9+/]+=*)"`)
	importFrom  = regexp.MustCompile(`(?m)^\s*(?:import|export)\b[^"';]*?\bfrom\s*["']([^"']+)["']|^\s*import\s*["']([^"']+)["']`)
	dynamicImpt = regexp.MustCompile(`\bimport\s*\(`)
)

func sri(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(file))
	require.NoError(t, err)
	sum := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

func moduleImports(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(file))
	require.NoError(t, err)
	require.False(t, dynamicImpt.Match(b), "%s: dynamic import() is not covered by SRI", file)
	out := make([]string, 0, 8)
	for _, m := range importFrom.FindAllStringSubmatch(string(b), -1) {
		spec := m[1] + m[2]
		require.True(t, strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"), "%s: non-relative import %s", file, spec)
		out = append(out, filepath.Join(filepath.Dir(file), spec))
	}
	return out
}

// Every script a portal page loads carries a subresource-integrity hash that
// matches the file served beside it, and so does every module those scripts
// import (through a modulepreload link: an integrity attribute on the entry
// script alone does not cover its imports). The CSP stays strict, so there
// is no inline import map. Run `make web-sri` after editing web/lib/*.js.
func TestPortalScriptsHaveIntegrity(t *testing.T) {
	t.Parallel()
	pages, err := filepath.Glob("*/index.html")
	require.NoError(t, err)
	require.NotEmpty(t, pages)
	for _, page := range pages {
		b, err := os.ReadFile(filepath.Clean(page))
		require.NoError(t, err)
		html := string(b)
		dir := filepath.Dir(page)

		declared := map[string]string{} // file -> integrity
		entries := make([]string, 0, 1)
		for _, tag := range scriptTag.FindAllString(html, -1) {
			src := attrSrc.FindStringSubmatch(tag)
			require.NotNil(t, src, "%s: script without src: %s", page, tag)
			hash := attrIntegr.FindStringSubmatch(tag)
			require.NotNil(t, hash, "%s: script without integrity: %s", page, tag)
			file := filepath.Join(dir, path.Clean(src[1]))
			require.Equal(t, sri(t, file), hash[1], "%s: stale integrity for %s", page, src[1])
			entries = append(entries, file)
		}
		require.NotEmpty(t, entries, page)
		// Preloads must precede the first script, or an import could be
		// fetched without a check before its preload is processed.
		if first := scriptTag.FindStringIndex(html); first != nil {
			for _, loc := range preloadTag.FindAllStringIndex(html, -1) {
				require.Less(t, loc[0], first[0], "%s: modulepreload after the module script", page)
			}
		}
		for _, tag := range preloadTag.FindAllString(html, -1) {
			href := attrHref.FindStringSubmatch(tag)
			hash := attrIntegr.FindStringSubmatch(tag)
			require.NotNil(t, href, "%s: modulepreload without href: %s", page, tag)
			require.NotNil(t, hash, "%s: modulepreload without integrity: %s", page, tag)
			file := filepath.Join(dir, path.Clean(href[1]))
			require.Equal(t, sri(t, file), hash[1], "%s: stale integrity for %s", page, href[1])
			declared[file] = hash[1]
		}

		seen := map[string]bool{}
		var walk func(string)
		walk = func(f string) {
			for _, dep := range moduleImports(t, f) {
				if seen[dep] {
					continue
				}
				seen[dep] = true
				require.Contains(t, declared, dep, "%s: imported module %s has no modulepreload with integrity", page, dep)
				walk(dep)
			}
		}
		for _, e := range entries {
			walk(e)
		}
	}
}
