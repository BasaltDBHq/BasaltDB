package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/portalverify"
	"github.com/basaltdbhq/basaltdb/internal/websec"
	"github.com/basaltdbhq/basaltdb/web"
)

type portalRun struct {
	code           int
	stdout, stderr string
}

func runPortalVerify(t *testing.T, args ...string) portalRun {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"portal", "verify"}, args...),
		stdio{in: strings.NewReader(""), out: &out, err: &errb})
	return portalRun{code, out.String(), errb.String()}
}

// portalFS is a writable copy of the embedded pages.
func portalFS(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := web.Files.ReadFile(p)
		m[p] = &fstest.MapFile{Data: b}
		return rerr
	}))
	return m
}

// portalHost serves files with the engine's headers, as the portal's
// _headers does. A test server stands in for portal.basaltvault.app.
func portalHost(t *testing.T, files fs.FS, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	// The portal's _redirects: each page route is rewritten (200) to its file.
	static := http.FileServer(http.FS(files))
	rewrite := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rt := range pages.PortalPages() {
			if r.URL.Path == rt.Path || (rt.ID && strings.HasPrefix(r.URL.Path, rt.Path)) {
				b, err := fs.ReadFile(files, rt.File)
				if err != nil {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(b)
				return
			}
		}
		static.ServeHTTP(w, r)
	})
	h := websec.Headers()(rewrite)
	if wrap != nil {
		h = wrap(h)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func requireLine(t *testing.T, out, status, path string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == status && f[1] == path {
			return
		}
	}
	require.Failf(t, "line not found", "want %s %s in:\n%s", status, path, out)
}

func TestPortalVerifyMatches(t *testing.T) {
	t.Parallel()
	url := portalHost(t, portalFS(t), nil)
	r := runPortalVerify(t, "--portal-url", url)
	require.Equal(t, exitOK, r.code, r.stdout+r.stderr)
	paths, err := fileList(web.Files)
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	for _, p := range paths {
		requireLine(t, r.stdout, "OK", p)
	}
	require.NotContains(t, r.stdout, "DIFFERS")
}

// make portal-build output is what the portal publishes; verify must pass
// against it too (skipped until the target has run, as web/embed_test.go).
func TestPortalVerifyMatchesBuiltPortal(t *testing.T) {
	t.Parallel()
	dist := "../../dist/portal"
	if _, err := os.Stat(dist); err != nil {
		t.Skip("run make portal-build first")
	}
	url := portalHost(t, os.DirFS(dist), nil)
	r := runPortalVerify(t, "--portal-url", url)
	require.Equal(t, exitOK, r.code, r.stdout+r.stderr)
	require.NotContains(t, r.stdout, "UNEXPECTED")
}

func fileList(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return err
	})
	return out, err
}

func TestPortalVerifyDetectsChange(t *testing.T) {
	t.Parallel()
	files := portalFS(t)
	b := append([]byte(nil), files["lib/codec.js"].Data...)
	b[len(b)/2] ^= 1
	files["lib/codec.js"] = &fstest.MapFile{Data: b}
	r := runPortalVerify(t, "--portal-url", portalHost(t, files, nil))
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "DIFFERS", "lib/codec.js")
	requireLine(t, r.stdout, "OK", "lib/page.js")
}

func TestPortalVerifyMissingAndExtra(t *testing.T) {
	t.Parallel()
	files := portalFS(t)
	delete(files, "lib/scope.js")
	files["lib/scope.test.mjs"] = &fstest.MapFile{Data: []byte("// a test the build must not publish")}
	r := runPortalVerify(t, "--portal-url", portalHost(t, files, nil))
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "MISSING", "lib/scope.js")
	requireLine(t, r.stdout, "UNEXPECTED", "lib/scope.test.mjs")

	// An extra file alone also fails.
	files = portalFS(t)
	files["embed.go"] = &fstest.MapFile{Data: []byte("package web")}
	r = runPortalVerify(t, "--portal-url", portalHost(t, files, nil))
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "UNEXPECTED", "embed.go")
}

func TestPortalVerifyChecksCSP(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(http.Header){
		"absent": func(h http.Header) { h.Del("Content-Security-Policy") },
		"weaker": func(h http.Header) { h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			url := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(&headerEdit{ResponseWriter: w, edit: mutate}, r)
				})
			})
			r := runPortalVerify(t, "--portal-url", url)
			require.Equal(t, exitError, r.code)
			requireLine(t, r.stdout, "HEADER", "approve/index.html")
			require.Contains(t, r.stdout, "Content-Security-Policy")
		})
	}
}

func TestPortalVerifyChecksScriptContentType(t *testing.T) {
	t.Parallel()
	url := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&headerEdit{ResponseWriter: w, edit: func(h http.Header) {
				if strings.HasSuffix(r.URL.Path, ".js") {
					h.Set("Content-Type", "text/plain")
				}
			}}, r)
		})
	})
	r := runPortalVerify(t, "--portal-url", url)
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "HEADER", "lib/codec.js")
	require.Contains(t, r.stdout, "text/javascript")
}

// headerEdit edits the headers just before they are written.
type headerEdit struct {
	http.ResponseWriter
	edit func(http.Header)
	done bool
}

func (h *headerEdit) WriteHeader(code int) {
	if !h.done {
		h.done = true
		h.edit(h.Header())
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerEdit) Write(b []byte) (int, error) {
	if !h.done {
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(b)
}

func TestPortalVerifyDoesNotFollowRedirectOffOrigin(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("attacker"))
	}))
	t.Cleanup(other.Close)
	url := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/lib/codec.js" {
				http.Redirect(w, r, other.URL+"/lib/codec.js", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r := runPortalVerify(t, "--portal-url", url)
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "ERROR", "lib/codec.js")
	require.Contains(t, r.stdout, "another origin")
	require.Zero(t, hits.Load(), "the other origin was never contacted")
}

func TestPortalVerifyFollowsRedirectWithinOrigin(t *testing.T) {
	t.Parallel()
	url := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/style.css" {
				http.Redirect(w, r, "/style-moved.css", http.StatusFound)
				return
			}
			if r.URL.Path == "/style-moved.css" {
				r.URL.Path = "/style.css"
			}
			next.ServeHTTP(w, r)
		})
	})
	r := runPortalVerify(t, "--portal-url", url)
	require.Equal(t, exitOK, r.code, r.stdout)
}

func TestPortalVerifyUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--portal-url", "http://portal.example.com"},
		{"--portal-url", "http://127.0.0.1.evil.example"},
		{"--portal-url", "ftp://localhost"},
		{"--portal-url", "https://user:pw@portal.example.com"},
		{"--portal-url", "https://portal.example.com/path"},
		{"--portal-url", "portal.example.com"},
		{"--bogus"},
		{"extra"},
		{"--manifest", filepath.Join(t.TempDir(), "missing")},
	} {
		r := runPortalVerify(t, args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
		require.Empty(t, r.stdout, "%v", args)
	}
	var out, errb bytes.Buffer
	require.Equal(t, exitUsage, run(context.Background(), []string{"portal"}, stdio{in: strings.NewReader(""), out: &out, err: &errb}))
	require.Equal(t, exitUsage, run(context.Background(), []string{"portal", "nope"}, stdio{in: strings.NewReader(""), out: &out, err: &errb}))
	// https and loopback http are accepted (the request itself fails here:
	// nothing listens, which is exit 1, not a usage error).
	for _, u := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		require.Equal(t, exitError, runPortalVerify(t, "--portal-url", u).code, u)
	}
}

func TestPortalVerifyManifest(t *testing.T) {
	t.Parallel()
	url := portalHost(t, portalFS(t), nil)
	// Without --manifest there is no manifest line: the binary would only
	// be checking itself.
	r := runPortalVerify(t, "--portal-url", url, "--json")
	require.Equal(t, exitOK, r.code, r.stdout)
	require.NotContains(t, r.stdout, "manifest")

	// The committed manifest matches the binary's pages (CRLF and upper-case
	// hex, as another tool may write them, are accepted).
	good, err := os.ReadFile("../../web/portal.sha256")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "manifest")
	require.NoError(t, os.WriteFile(path, bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")), 0o600))
	r = runPortalVerify(t, "--portal-url", url, "--manifest", path, "--json")
	require.Equal(t, exitOK, r.code, r.stdout)
	var rep struct {
		Manifest struct{ Source, Status string }
	}
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &rep))
	require.Equal(t, path, rep.Manifest.Source)
	require.Equal(t, "OK", rep.Manifest.Status)

	// A manifest that disagrees with the binary fails.
	bad := strings.Replace(string(good), string(good[:64]), strings.Repeat("0", 64), 1)
	require.NoError(t, os.WriteFile(path, []byte(bad), 0o600))
	r = runPortalVerify(t, "--portal-url", url, "--manifest", path)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "DIFFERS    release manifest ("+path)
	require.Contains(t, r.stdout, "differs from the manifest")
	// The pages themselves still match the portal.
	require.NotContains(t, r.stdout, "\nDIFFERS    approve")

	// A malformed or duplicated manifest is a usage error.
	for _, body := range []string{"not a manifest\n", string(good) + string(good[:66]) + "approve/index.html\n"} {
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		require.Equal(t, exitUsage, runPortalVerify(t, "--portal-url", url, "--manifest", path).code)
	}
}

// People load the pages at the routes the _redirects rewrites, not at
// /approve/: a portal that rewrites a route to another page, or sends a
// weaker policy only there, must fail even when the page files are intact.
func TestPortalVerifyChecksTheRoutesPeopleLoad(t *testing.T) {
	t.Parallel()
	good := portalHost(t, portalFS(t), nil)
	r := runPortalVerify(t, "--portal-url", good)
	require.Equal(t, exitOK, r.code, r.stdout)
	requireLine(t, r.stdout, "OK", "/approvals/"+portalverify.ProbeID)
	requireLine(t, r.stdout, "OK", "/passkeys/forget")

	evil := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/approvals/") {
				_, _ = w.Write([]byte("<html>sign here</html>"))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r = runPortalVerify(t, "--portal-url", evil)
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "DIFFERS", "/approvals/"+portalverify.ProbeID)
	requireLine(t, r.stdout, "OK", "approve/index.html")

	weak := portalHost(t, portalFS(t), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&headerEdit{ResponseWriter: w, edit: func(h http.Header) {
				if strings.HasPrefix(r.URL.Path, "/reverts/") {
					h.Set("Content-Security-Policy", "default-src *")
				}
			}}, r)
		})
	})
	r = runPortalVerify(t, "--portal-url", weak)
	require.Equal(t, exitError, r.code)
	requireLine(t, r.stdout, "HEADER", "/reverts/"+portalverify.ProbeID)
	requireLine(t, r.stdout, "OK", "revert/index.html")
}

func TestPortalVerifyJSONMatchesSchema(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/mcp/portal/portal-verify-result.schema.json")
	require.NoError(t, err)
	var schema map[string]any
	require.NoError(t, json.Unmarshal(raw, &schema))

	files := portalFS(t)
	delete(files, "lib/scope.js")
	files["embed.go"] = &fstest.MapFile{Data: []byte("package web")}
	bad := portalHost(t, files, nil)
	good := portalHost(t, portalFS(t), nil)
	for _, url := range []string{good, bad, "http://127.0.0.1:1"} {
		r := runPortalVerify(t, "--portal-url", url, "--json")
		var v any
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &v), r.stdout)
		validateJSON(t, "$", schema, v)
		require.Empty(t, r.stderr)
	}
	r := runPortalVerify(t, "--portal-url", good, "--json")
	require.Equal(t, exitOK, r.code)
	require.Contains(t, r.stdout, `"ok": true`)
	require.Equal(t, exitError, runPortalVerify(t, "--portal-url", bad, "--json").code)
}

// validateJSON checks v against the subset of JSON Schema the contract's
// schema files use: type, enum, required, properties, additionalProperties
// false, items and minimum.
func validateJSON(t *testing.T, at string, schema map[string]any, v any) {
	t.Helper()
	if enum, ok := schema["enum"].([]any); ok {
		require.Contains(t, enum, v, at)
	}
	switch schema["type"] {
	case "object":
		obj, ok := v.(map[string]any)
		require.True(t, ok, "%s is not an object: %v", at, v)
		props, _ := schema["properties"].(map[string]any)
		if req, ok := schema["required"].([]any); ok {
			for _, k := range req {
				require.Contains(t, obj, k, at)
			}
		}
		for k, val := range obj {
			sub, known := props[k].(map[string]any)
			if schema["additionalProperties"] == false {
				require.True(t, known, "%s: unknown key %q", at, k)
			}
			if known {
				validateJSON(t, at+"."+k, sub, val)
			}
		}
	case "array":
		arr, ok := v.([]any)
		require.True(t, ok, "%s is not an array", at)
		if items, ok := schema["items"].(map[string]any); ok {
			for i, e := range arr {
				validateJSON(t, at+"[]"+string(rune('0'+i%10)), items, e)
			}
		}
	case "string":
		require.IsType(t, "", v, at)
	case "boolean":
		require.IsType(t, true, v, at)
	case "integer":
		n, ok := v.(float64)
		require.True(t, ok && n == float64(int64(n)), at)
		if lo, ok := schema["minimum"].(float64); ok {
			require.GreaterOrEqual(t, n, lo, at)
		}
	}
}
