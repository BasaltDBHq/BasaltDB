package web_test

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/web"
)

var (
	scriptTag   = regexp.MustCompile(`(?is)<script\b[^>]*>`)
	preloadTag  = regexp.MustCompile(`(?is)<link\b[^>]*\bmodulepreload\b[^>]*>`)
	attrSrc     = regexp.MustCompile(`\bsrc="([^"]+)"`)
	attrHref    = regexp.MustCompile(`\bhref="([^"]+)"`)
	attrIntegr  = regexp.MustCompile(`\bintegrity="(sha384-[A-Za-z0-9+/]+=*)"`)
	importFrom  = regexp.MustCompile(`(?m)^\s*(?:import|export)\b[^"';]*?\bfrom\s*["']([^"']+)["']|^\s*import\s*["']([^"']+)["']`)
	dynamicImpt = regexp.MustCompile(`\bimport\s*\(`)
)

// resolve turns a reference in a page or module into a path inside fsys and
// fails when that file is not there. The tests read web.Files, so a
// reference to a file that sits in web/ but is not embedded (the engine and
// the portal would answer 404, or worse, serve something else) fails too.
func resolve(fsys fs.FS, from, ref string) (string, error) {
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") || strings.HasPrefix(ref, "/") {
		return "", fmt.Errorf("%s: reference %s is not relative to the page", from, ref)
	}
	p := path.Join(path.Dir(from), ref)
	if !fs.ValidPath(p) {
		return "", fmt.Errorf("%s: reference %s leaves the embedded files", from, ref)
	}
	if _, err := fs.Stat(fsys, p); err != nil {
		return "", fmt.Errorf("%s: reference %s is not an embedded file", from, ref)
	}
	return p, nil
}

func sri(fsys fs.FS, file string) (string, error) {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", err
	}
	sum := sha512.Sum384(b)
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

func moduleImports(fsys fs.FS, file string) ([]string, error) {
	b, err := fs.ReadFile(fsys, file)
	if err != nil {
		return nil, err
	}
	if dynamicImpt.Match(b) {
		return nil, fmt.Errorf("%s: dynamic import() is not covered by SRI", file)
	}
	out := make([]string, 0, 8)
	for _, m := range importFrom.FindAllStringSubmatch(string(b), -1) {
		spec := m[1] + m[2]
		if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
			return nil, fmt.Errorf("%s: non-relative import %s", file, spec)
		}
		dep, err := resolve(fsys, file, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, dep)
	}
	return out, nil
}

// pinned checks one script or modulepreload tag: it names an embedded file
// and carries that file's sha384 integrity hash. It returns the file.
func pinned(fsys fs.FS, page, tag string, attr *regexp.Regexp) (string, error) {
	ref := attr.FindStringSubmatch(tag)
	if ref == nil {
		return "", fmt.Errorf("%s: tag without a reference: %s", page, tag)
	}
	hash := attrIntegr.FindStringSubmatch(tag)
	if hash == nil {
		return "", fmt.Errorf("%s: tag without integrity: %s", page, tag)
	}
	file, err := resolve(fsys, page, ref[1])
	if err != nil {
		return "", err
	}
	want, err := sri(fsys, file)
	if err != nil {
		return "", err
	}
	if want != hash[1] {
		return "", fmt.Errorf("%s: stale integrity for %s", page, ref[1])
	}
	return file, nil
}

// checkPageSRI checks every script and modulepreload tag of one page,
// anywhere in the page (inside the generated sri block or not), against the
// files in fsys, and that every module the scripts import, directly or not,
// has a modulepreload with integrity placed before the first script.
func checkPageSRI(fsys fs.FS, page string) error {
	b, err := fs.ReadFile(fsys, page)
	if err != nil {
		return err
	}
	html := string(b)

	declared := map[string]bool{}
	entries := make([]string, 0, 1)
	for _, tag := range scriptTag.FindAllString(html, -1) {
		file, err := pinned(fsys, page, tag, attrSrc)
		if err != nil {
			return err
		}
		entries = append(entries, file)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: no script", page)
	}
	first := scriptTag.FindStringIndex(html)
	for _, loc := range preloadTag.FindAllStringIndex(html, -1) {
		if loc[0] > first[0] {
			return fmt.Errorf("%s: modulepreload after the module script", page)
		}
	}
	for _, tag := range preloadTag.FindAllString(html, -1) {
		file, err := pinned(fsys, page, tag, attrHref)
		if err != nil {
			return err
		}
		declared[file] = true
	}

	seen := map[string]bool{}
	var walk func(string) error
	walk = func(f string) error {
		deps, err := moduleImports(fsys, f)
		if err != nil {
			return err
		}
		for _, dep := range deps {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			if !declared[dep] {
				return fmt.Errorf("%s: imported module %s has no modulepreload with integrity", page, dep)
			}
			if err := walk(dep); err != nil {
				return err
			}
		}
		return nil
	}
	for _, e := range entries {
		if err := walk(e); err != nil {
			return err
		}
	}
	return nil
}

// Every script a portal page loads carries a subresource-integrity hash that
// matches the embedded file it names (web.Files: what the engine and the
// portal serve), and so does every module those scripts import (through a
// modulepreload link: an integrity attribute on the entry script alone does
// not cover its imports). The CSP stays strict, so there is no inline import
// map. Run `make web-sri` after editing web/lib/*.js.
func TestPortalScriptsHaveIntegrity(t *testing.T) {
	t.Parallel()
	pages, err := fs.Glob(web.Files, "*/index.html")
	require.NoError(t, err)
	require.NotEmpty(t, pages)
	for _, page := range pages {
		require.NoError(t, checkPageSRI(web.Files, page))
	}
}

// The check must fail on a reference to a file that exists in web/ but is
// not embedded, even with a correct hash and even after the generated block.
func TestPortalSRICheckRejects(t *testing.T) {
	t.Parallel()
	const page = "approve/index.html"
	base := fstest.MapFS{}
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(web.Files, p)
		base[p] = &fstest.MapFile{Data: b}
		return err
	}))
	html := string(base[page].Data)
	require.NoError(t, checkPageSRI(base, page))

	// portal.sha256 sits in web/ but is not embedded: give it a correct hash.
	outside := []byte("not embedded\n")
	sum := sha512.Sum384(outside)
	good := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
	notEmbedded := `<script type="module" src="../portal.sha256" integrity="` + good + `"></script>`
	approveHash, err := sri(base, "lib/approve.js")
	require.NoError(t, err)

	cases := map[string]struct {
		html, want string
	}{
		"script to a file not embedded, before the block": {
			strings.Replace(html, "<!-- sri:begin", notEmbedded+"\n<!-- sri:begin", 1), "not an embedded file",
		},
		"script to a file not embedded, after the block": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+notEmbedded, 1), "not an embedded file",
		},
		"modulepreload to a file not embedded": {
			strings.Replace(html, "<!-- sri:begin (generated by scripts/web-sri.mjs; do not edit) -->",
				`<link rel="modulepreload" href="../portal.sha256" integrity="`+good+`">`, 1), "not an embedded file",
		},
		"reference outside the embedded tree": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<script type="module" src="../../go.mod" integrity="`+good+`"></script>`, 1), "leaves the embedded files",
		},
		"absolute reference": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<script type="module" src="https://example.com/x.js" integrity="`+good+`"></script>`, 1), "not relative",
		},
		"script after the block without integrity": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<script type="module" src="../lib/approve.js"></script>`, 1), "without integrity",
		},
		"stale hash": {
			strings.Replace(html, approveHash, good, 1), "stale integrity",
		},
	}
	for name, c := range cases {
		require.NotEqual(t, html, c.html, name)
		fsys := fstest.MapFS{}
		for k, v := range base {
			fsys[k] = v
		}
		fsys[page] = &fstest.MapFile{Data: []byte(c.html)}
		err := checkPageSRI(fsys, page)
		require.Error(t, err, name)
		require.Contains(t, err.Error(), c.want, name)
	}
}
