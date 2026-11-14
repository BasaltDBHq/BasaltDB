package web_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/web"
)

var (
	// anyTag finds every script or link tag, in any case or spelling. Each
	// must have exactly one of the forms below (what scripts/web-sri.mjs
	// writes); any other shape fails, so a decoy attribute (data-src=, a
	// src="..." inside another value) cannot point the check at one file
	// while the browser loads another.
	anyTag      = regexp.MustCompile(`(?i)<(script|link)\b`)
	scriptForm  = regexp.MustCompile(`^<script type="module" src="([^"&]+)" integrity="(sha384-[A-Za-z0-9+/]+=*)"></script>`)
	preloadForm = regexp.MustCompile(`^<link rel="modulepreload" href="([^"&]+)" integrity="(sha384-[A-Za-z0-9+/]+=*)">`)
	styleForm   = regexp.MustCompile(`^<link rel="stylesheet" href="([^"&]+)">`)
	// importFrom reads a static import (or export ... from) that starts a
	// line. Its clause holds no quote, semicolon, parenthesis or slash, so it
	// cannot swallow an import() call, a second statement or a comment.
	importFrom = regexp.MustCompile("(?m)^[ \t]*(?:import|export)\\b[^\"';()`/]*?\\bfrom[ \t]*[\"']([^\"']+)[\"']|^[ \t]*import[ \t]*[\"']([^\"']+)[\"']")
	// dynamicImpt is import( with JavaScript white space or // comments
	// between (block comments are refused outright, see moduleImports).
	dynamicImpt = regexp.MustCompile(`\bimport(?:` + jsSpace + `|//[^\n]*\n)*\(`)
	// strayImport is an import or export-from that importFrom did not read:
	// one not at the start of a line, import.meta, or the word in a string or
	// comment. Comments are not skipped: a line that starts with // can still
	// end a template literal or a continued string and go on as code.
	strayImport = regexp.MustCompile("\\bimport\\b|\\bfrom" + jsSpace + "*[\"'`]")
	// unpinnedLoad is a way to run code or load a document that no
	// modulepreload integrity covers: script elements (any "script" string,
	// createElementNS for the SVG one), workers, worklets, frames, objects
	// and embeds. It catches a mistake, not deliberate
	// obfuscation ("scr" + "ipt"). The pages' meta CSP (default-src 'none')
	// blocks frames and objects as well, but not script elements or workers:
	// script-src 'self' admits any same-origin script without integrity.
	unpinnedLoad = regexp.MustCompile("(?i)\\b(?:worker|sharedworker|serviceworker|importscripts|[a-z]*worklet|addmodule|iframe|frameset|srcdoc|htmliframeelement|htmlobjectelement|htmlembedelement|htmlscriptelement|svgscriptelement|createelementns)\\b" +
		"|[\"'`]script[\"'`]|<" + jsSpace + "*(?:script|frame|object|embed|portal|applet)\\b|\\(" + jsSpace + "*[\"'`](?:frame|object|embed|portal|applet)[\"'`]")
)

// jsSpace is one character JavaScript's \s matches (U+2028, U+2029 and CR
// are refused in modules), so the Go and node checks agree.
const jsSpace = "[\\t\\n\\v\\f \\x{a0}\\x{1680}\\x{2000}-\\x{200a}\\x{202f}\\x{205f}\\x{3000}\\x{feff}]"

// resolve turns a reference in a page or module into a path inside fsys and
// fails when that file is not there. The tests read web.Files, so a
// reference to a file that sits in web/ but is not embedded (the engine and
// the portal would answer 404, or worse, serve something else) fails too.
func resolve(fsys fs.FS, from, ref string) (string, error) {
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") || strings.HasPrefix(ref, "/") {
		return "", fmt.Errorf("%s: reference %s is not relative to the page", from, ref)
	}
	if c := path.Clean(ref); c != ref && "./"+c != ref {
		// The browser keys a module by its URL as written: a preload of
		// ../lib//x.js would not cover the import of ../lib/x.js.
		return "", fmt.Errorf("%s: reference %s is not in clean form", from, ref)
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

var charsetDecl = regexp.MustCompile(`(?i)charset`)

// plainUTF8 refuses a page the browser might decode differently from the
// check: a byte-order mark (it overrides the declared charset, so a UTF-16
// page would hide its tags from a byte-level scan), invalid UTF-8, control
// bytes other than tab, LF and CR (ESC switches ISO-2022 encodings), or any
// charset other than one <meta charset="utf-8"> in the first 1024 bytes.
func plainUTF8(page string, b []byte) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("%s: not valid UTF-8", page)
	}
	if bytes.HasPrefix(b, []byte("\uFEFF")) {
		return fmt.Errorf("%s: starts with a byte-order mark", page)
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return fmt.Errorf("%s: control byte 0x%02x", page, c)
		}
	}
	const meta = `<meta charset="utf-8">`
	i := bytes.Index(b, []byte(meta))
	if i < 0 || i+len(meta) > 1024 || len(charsetDecl.FindAllIndex(b, -1)) != 1 {
		return fmt.Errorf("%s: must declare exactly one charset, %s, in its first 1024 bytes", page, meta)
	}
	return nil
}

const (
	sriBegin = "<!-- sri:begin (generated by scripts/web-sri.mjs; do not edit) -->"
	sriEnd   = "<!-- sri:end -->"
	prologue = "<!doctype html>\n<html lang=\"en\">\n<head>\n"
)

// headLine lists the only lines a page head may hold besides the sri block.
// Each is a whole, self-contained tag: none can open a context (template,
// noscript, an attribute value, title text) that would make the block inert
// to the browser while the checks still read it.
var headLine = regexp.MustCompile(`^(?:` + strings.Join([]string{
	`<meta charset="utf-8">`,
	`<meta name="viewport" content="width=device-width, initial-scale=1">`,
	`<meta name="referrer" content="no-referrer">`,
	`<meta name="robots" content="noindex">`,
	`<title>[^<>&"]*</title>`,
	`<link rel="stylesheet" href="[^"&]+">`,
}, "|") + `)$`)

// cspLine is the meta CSP every page carries, before its sri block: it
// falls back to default-src 'none', so frames and objects stay blocked even
// where a host serves the page under a looser header (the portal's _headers
// falls back to 'self'). It does not block workers or script elements
// (script-src 'self'). Only connect-src may differ.
var cspLine = regexp.MustCompile(`^<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src '(?:self|none)'; base-uri 'none'; form-action 'none'">$`)

var (
	preloadLine = regexp.MustCompile(preloadForm.String() + `$`)
	scriptLine  = regexp.MustCompile(scriptForm.String() + `$`)
)

// bodyTag is a tag the body may not hold: one that loads a script, sets
// page metadata, or frames or embeds another document (an <iframe srcdoc>
// would run markup that no integrity check reads).
var bodyTag = regexp.MustCompile(`(?i)<(script|link|meta|base|head|iframe|frame|frameset|object|embed|portal|applet)\b`)

// pageShape pins where the sri block sits: the page starts with the fixed
// prologue, its head holds only allow-listed lines, exactly one meta CSP
// line (cspLine) and exactly one sri block (the preloads, then one module
// script), and nothing after </head> is a bodyTag.
func pageShape(page, html string) error {
	if !strings.HasPrefix(html, prologue) {
		return fmt.Errorf("%s: does not start with the fixed prologue", page)
	}
	head, body, ok := strings.Cut(html[len(prologue):], "\n</head>\n")
	if !ok {
		return fmt.Errorf("%s: no </head> line", page)
	}
	if m := bodyTag.FindString(body); m != "" {
		return fmt.Errorf("%s: %s after the head", page, m)
	}
	const (
		before = iota
		preloads
		after
	)
	state := before
	csp := 0
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimLeft(line, " ")
		switch {
		case state == before && cspLine.MatchString(line):
			csp++
		case strings.HasPrefix(line, `<meta http-equiv="Content-Security-Policy"`):
			return fmt.Errorf("%s: the meta CSP line must be the fixed one, with default-src 'none', before the sri block: %s", page, line)
		case state == before && line == sriBegin:
			state = preloads
		case state == preloads && preloadLine.MatchString(line):
		case state == preloads && scriptLine.MatchString(line):
			state = -state // script seen; only the end comment may follow
		case state == -preloads && line == sriEnd:
			state = after
		case state != preloads && state != -preloads && headLine.MatchString(line):
		default:
			return fmt.Errorf("%s: head line is not in a checked form (run make web-sri): %s", page, line)
		}
	}
	if state != after {
		return fmt.Errorf("%s: no complete sri block in the head", page)
	}
	if csp != 1 {
		return fmt.Errorf("%s: needs exactly one meta CSP line with default-src 'none', before the sri block (found %d)", page, csp)
	}
	return nil
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
	src := string(b)
	if strings.ContainsAny(src, "\r\u2028\u2029") {
		// JavaScript ends a line (and a // comment) at each of these.
		return nil, fmt.Errorf("%s: line terminator other than LF", file)
	}
	if strings.Contains(src, "/*") {
		// A block comment can make the line-based reading below see code as
		// commented out, or the other way round, so modules use // only.
		return nil, fmt.Errorf("%s: block comment (use // comments)", file)
	}
	if dynamicImpt.MatchString(src) {
		return nil, fmt.Errorf("%s: dynamic import() is not covered by SRI", file)
	}
	if m := unpinnedLoad.FindString(src); m != "" {
		return nil, fmt.Errorf("%s: %s loads code or a document that SRI does not cover", file, m)
	}
	code := src
	matches := importFrom.FindAllStringSubmatchIndex(code, -1)
	var rest strings.Builder
	last := 0
	for _, m := range matches {
		rest.WriteString(code[last:m[0]])
		rest.WriteString(" ")
		last = m[1]
	}
	rest.WriteString(code[last:])
	if m := strayImport.FindString(rest.String()); m != "" {
		return nil, fmt.Errorf("%s: an import the scanner cannot account for (%s); write each import at the start of a line", file, m)
	}
	out := make([]string, 0, 8)
	for _, m := range importFrom.FindAllStringSubmatch(code, -1) {
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

// pinned checks that ref names an embedded file whose sha384 is hash, and
// returns the file.
func pinned(fsys fs.FS, page, ref, hash string) (string, error) {
	file, err := resolve(fsys, page, ref)
	if err != nil {
		return "", err
	}
	want, err := sri(fsys, file)
	if err != nil {
		return "", err
	}
	if want != hash {
		return "", fmt.Errorf("%s: stale integrity for %s", page, ref)
	}
	return file, nil
}

// checkPageSRI checks every script and link tag of one page, anywhere in the
// page (inside the generated sri block or not): each has one of the exact
// forms above, every script and modulepreload names an embedded file and
// carries its hash, the preloads come before the first script, and every
// module the scripts import, directly or not, has a modulepreload.
func checkPageSRI(fsys fs.FS, page string) error {
	b, err := fs.ReadFile(fsys, page)
	if err != nil {
		return err
	}
	if err := plainUTF8(page, b); err != nil {
		return err
	}
	html := string(b)

	declared := map[string]bool{}
	entries := make([]string, 0, 1)
	for _, loc := range anyTag.FindAllStringIndex(html, -1) {
		rest := html[loc[0]:]
		tag, _, _ := strings.Cut(rest, ">")
		if m := scriptForm.FindStringSubmatch(rest); m != nil {
			file, err := pinned(fsys, page, m[1], m[2])
			if err != nil {
				return err
			}
			entries = append(entries, file)
			continue
		}
		if m := preloadForm.FindStringSubmatch(rest); m != nil {
			if len(entries) > 0 {
				return fmt.Errorf("%s: modulepreload after the module script", page)
			}
			file, err := pinned(fsys, page, m[1], m[2])
			if err != nil {
				return err
			}
			declared[file] = true
			continue
		}
		if m := styleForm.FindStringSubmatch(rest); m != nil {
			if _, err := resolve(fsys, page, m[1]); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("%s: tag is not in a checked form (run make web-sri): %s>", page, tag)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: no script", page)
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
	return pageShape(page, html)
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
	cspLine := cspLineRe.FindString(html)
	require.NotEmpty(t, cspLine)

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
				`<script type="module" src="../lib/approve.js"></script>`, 1), "not in a checked form",
		},
		"decoy data- attributes": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<script type="module" data-src="../lib/approve.js" data-integrity="`+approveHash+`" src="../portal.sha256" integrity="`+good+`"></script>`, 1), "not in a checked form",
		},
		"decoy inside another attribute": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<script type="module" title='src="../lib/approve.js" integrity="`+approveHash+`"' src="../portal.sha256" integrity="`+good+`"></script>`, 1), "not in a checked form",
		},
		"entity-encoded modulepreload": {
			strings.Replace(html, "<!-- sri:begin", `<link rel="module&#112;reload" href="../portal.sha256">`+"\n<!-- sri:begin", 1), "not in a checked form",
		},
		"uppercase script tag": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<SCRIPT type="module" src="../portal.sha256" integrity="`+good+`"></SCRIPT>`, 1), "not in a checked form",
		},
		"stylesheet not embedded": {
			strings.Replace(html, `href="../style.css"`, `href="../portal.sha256"`, 1), "not an embedded file",
		},
		"modulepreload after the script": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+
				`<link rel="modulepreload" href="../lib/approve.js" integrity="`+approveHash+`">`, 1), "after the module script",
		},
		"utf-16 page with a byte-order mark": {
			utf16le(strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n"+notEmbedded, 1)), "not valid UTF-8",
		},
		"utf-8 byte-order mark": {"\uFEFF" + html, "byte-order mark"},
		"escape byte":           {strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n<scr\x1b(Bipt>", 1), "control byte"},
		"second charset": {
			strings.Replace(html, `<meta charset="utf-8">`, `<meta charset="utf-8">`+"\n"+`<meta charset="ISO-2022-JP">`, 1), "exactly one charset",
		},
		"no charset": {strings.Replace(html, `<meta charset="utf-8">`, "", 1), "exactly one charset"},
		"preload not in clean form": {
			strings.Replace(html, `href="../lib/changes.js"`, `href="../lib//changes.js"`, 1), "not in clean form",
		},
		"block inside a template": {
			strings.Replace(strings.Replace(html, "<!-- sri:begin", "<template>\n<!-- sri:begin", 1), "<!-- sri:end -->",
				"<!-- sri:end -->\n</template>\n"+`<script type="module" src="../lib/approve.js" integrity="`+approveHash+`"></script>`, 1),
			"not in a checked form",
		},
		"block inside noscript": {
			strings.Replace(strings.Replace(html, "<!-- sri:begin", "<noscript>\n<!-- sri:begin", 1), "<!-- sri:end -->",
				"<!-- sri:end -->\n</noscript>\n"+`<script type="module" src="../lib/approve.js" integrity="`+approveHash+`"></script>`, 1),
			"not in a checked form",
		},
		"block inside an attribute value": {
			strings.Replace(strings.Replace(html, "<!-- sri:begin", "<meta name='x' content='\n<!-- sri:begin", 1), "<!-- sri:end -->",
				"<!-- sri:end -->\n'>\n"+`<script type="module" src="../lib/approve.js" integrity="`+approveHash+`"></script>`, 1),
			"not in a checked form",
		},
		"two sri blocks": {
			strings.Replace(html, "<!-- sri:end -->", "<!-- sri:end -->\n<!-- sri:begin (generated by scripts/web-sri.mjs; do not edit) -->\n"+
				`<script type="module" src="../lib/approve.js" integrity="`+approveHash+`"></script>`+"\n<!-- sri:end -->", 1),
			"not in a checked form",
		},
		"text after a preload": {
			strings.Replace(html, `integrity="`+approveHash+`"></script>`, `integrity="`+approveHash+`"></script>x`, 1),
			"not in a checked form",
		},
		"entity-encoded charset in the body": {
			strings.Replace(html, "</body>", `<meta http-equiv="content-type" content="text/html; ch&#97;rset=Shift_JIS">`+"\n</body>", 1),
			"after the head",
		},
		"stale hash": {
			strings.Replace(html, approveHash, good, 1), "stale integrity",
		},
		"no meta CSP line": {
			strings.Replace(html, cspLine, "", 1), "meta CSP line",
		},
		"meta CSP without default-src 'none'": {
			strings.Replace(html, "default-src 'none'", "default-src 'self'", 1), "meta CSP line",
		},
		"meta CSP that allows frames": {
			strings.Replace(html, "form-action 'none'\">", "form-action 'none'; frame-src 'self'\">", 1), "meta CSP line",
		},
		"meta CSP after the sri block": {
			strings.Replace(strings.Replace(html, cspLine, "", 1), "<!-- sri:end -->\n", "<!-- sri:end -->\n"+cspLine, 1),
			"meta CSP line",
		},
		"two meta CSP lines": {
			strings.Replace(html, "  <!-- sri:begin", cspLine+"  <!-- sri:begin", 1), "meta CSP line",
		},
		"iframe srcdoc in the body": {
			strings.Replace(html, "</body>", `<iframe srcdoc="&lt;script type=module src=../portal.sha256&gt;&lt;/script&gt;"></iframe>`+"\n</body>", 1),
			"<iframe after the head",
		},
		"object in the body": {
			strings.Replace(html, "</body>", `<object data="../portal.sha256"></object>`+"\n</body>", 1), "<object after the head",
		},
		"embed in the body": {
			strings.Replace(html, "</body>", `<EMBED src="../portal.sha256">`+"\n</body>", 1), "<EMBED after the head",
		},
		"frameset in the body": {
			strings.Replace(html, "</body>", `<frameset><frame src="../portal.sha256"></frameset>`+"\n</body>", 1), "<frame",
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

var cspLineRe = regexp.MustCompile(`[ ]*<meta http-equiv="Content-Security-Policy"[^\n]*\n`)

// The module scanner must refuse every way a pinned module could load code
// (or a document) that no modulepreload integrity covers, instead of
// missing an import it cannot read.
func TestPortalModuleScanRejects(t *testing.T) {
	t.Parallel()
	dep := "export const a = 1;\n"
	ok := []string{
		"import { a } from \"./a.js\";\nexport const b = a;\n",
		"import {\n  a,\n} from \"./a.js\";\n",
		"export { a } from \"./a.js\";\n",
		"// Tests load this module without a document.\nimport { a } from \"./a.js\";\n",
		"  // WebAuthn reports \"x\" and \"y\" the same way.\nconst k = await subtle.importKey(\"raw\", s, \"HKDF\", false, []);\nif (typeof v === \"object\") {}\n",
	}
	for _, src := range ok {
		_, err := moduleImports(fstest.MapFS{"lib/m.js": {Data: []byte(src)}, "lib/a.js": {Data: []byte(dep)}}, "lib/m.js")
		require.NoError(t, err, src)
	}
	cases := map[string]struct{ src, want string }{
		"import not at line start":             {"const x = 1; import { a } from \"./a.js\";\n", "cannot account for"},
		"export-from not at line start":        {"const x = 1; export { a } from \"./a.js\";\n", "cannot account for"},
		"import after a block comment":         {"/* x */ import { a } from \"./a.js\";\n", "block comment"},
		"import call hidden in a clause":       {"import(x)\nfrom\n\"./a.js\";\n", "dynamic import"},
		"dynamic import":                       {"await import(\"./a.js\");\n", "dynamic import"},
		"dynamic import with a comment":        {"await import/**/(\"./a.js\");\n", "block comment"},
		"dynamic import with comments":         {"await import /* a */ /* b */ (\"./a.js\");\n", "block comment"},
		"import.meta":                          {"const u = import.meta.url;\n", "cannot account for"},
		"import in a string":                   {"const s = \"x\"; const t = \"import\";\n", "cannot account for"},
		"import in a comment":                  {"// Tests import this module.\nconst a = 1;\n", "cannot account for"},
		"line comment ended by U+2028":         {"// note await import(\"./a.js\");\n", "line terminator"},
		"carriage return":                      {"// note\rawait import(\"./a.js\");\n", "line terminator"},
		"import call in a template line":       {"const s = `\n// ${await import(\"./a.js\")}\n`;\n", "dynamic import"},
		"worker in a template line":            {"const s = `\n// ${new Worker(\"./a.js\")}\n`;\n", "SRI does not cover"},
		"import after a // */ line":            {"/*\n// */ import { a } from \"./a.js\";\n", "block comment"},
		"import() behind a // from":            {"import // from \"./a.js\"\n(\"./a.js\");\n", "dynamic import"},
		"bare import behind a /* from */":      {"import /* from \"./a.js\" */ \"./a.js\";\n", "block comment"},
		"import() with a nbsp":                 {"const s = `\n// ${await import\u00a0(\"./a.js\")}\n`;\n", "dynamic import"},
		"nbsp before an import":                {"\u00a0import { a } from \"./a.js\";\n", "cannot account for"},
		"script element":                       {"const s = document.createElement(\"script\");\n", "SRI does not cover"},
		"script in markup":                     {"d.innerHTML = \"<script src=x></script>\";\n", "SRI does not cover"},
		"import after a template on a // line": {"const h = `\n// `; import { a } from \"./a.js\";\n", "cannot account for"},
		"import after a continued string":      {"const h = \"\\\n// \"; import \"./a.js\";\n", "cannot account for"},
		"svg script element":                   {"document.createElementNS(\"http://www.w3.org/2000/svg\", \"script\");\n", "SRI does not cover"},
		"script tag name in a variable":        {"const tag = \"script\";\ndocument.createElement(tag);\n", "SRI does not cover"},
		"createElementNS":                      {"document.createElementNS(ns, tag);\n", "SRI does not cover"},
		"module worker":                        {"new Worker(\"./a.js\", { type: \"module\" });\n", "SRI does not cover"},
		"shared worker":                        {"new SharedWorker(\"./a.js\");\n", "SRI does not cover"},
		"worker by name":                       {"new self[\"Worker\"](\"./a.js\");\n", "SRI does not cover"},
		"service worker":                       {"navigator.serviceWorker.register(\"./a.js\");\n", "SRI does not cover"},
		"importScripts":                        {"importScripts(\"./a.js\");\n", "SRI does not cover"},
		"worklet":                              {"CSS.paintWorklet.addModule(\"./a.js\");\n", "SRI does not cover"},
		"iframe element":                       {"document.body.append(el(\"iframe\"));\n", "SRI does not cover"},
		"srcdoc property":                      {"f.srcdoc = s;\n", "SRI does not cover"},
		"object element":                       {"document.createElement(\"object\");\n", "SRI does not cover"},
		"embed element":                        {"document.createElement('embed');\n", "SRI does not cover"},
		"embed in markup":                      {"d.innerHTML = \"<embed src=x>\";\n", "SRI does not cover"},
		"object in markup":                     {"d.innerHTML = `<object data=x>`;\n", "SRI does not cover"},
		"frame in markup":                      {"d.innerHTML = \"< frame src=x>\";\n", "SRI does not cover"},
	}
	for name, c := range cases {
		_, err := moduleImports(fstest.MapFS{"lib/m.js": {Data: []byte(c.src)}, "lib/a.js": {Data: []byte(dep)}}, "lib/m.js")
		require.Error(t, err, name)
		require.Contains(t, err.Error(), c.want, name)
	}
}

// utf16le encodes s as UTF-16LE with a byte-order mark, as a browser would
// decode it regardless of the declared charset.
func utf16le(s string) string {
	out := make([]byte, 0, 2+2*len(s))
	out = append(out, 0xff, 0xfe)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return string(out)
}
