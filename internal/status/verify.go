package status

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/textproto"
	"net/url"
	"path"
	"slices"
	"strings"
)

// Statuses of one path.
const (
	StatusOK         = "OK"
	StatusDiffers    = "DIFFERS"    // served, different bytes
	StatusMissing    = "MISSING"    // embedded but not served
	StatusUnexpected = "UNEXPECTED" // served but not embedded
	StatusHeader     = "HEADER"     // right bytes, wrong response header
	StatusError      = "ERROR"      // could not be checked
)

// maxBody bounds what is read for one file; the largest embedded file is
// far smaller, so a longer body is a different file.
const maxBody = 4 << 20

// The HTTP status codes the check reads.
const (
	codeOK        = 200
	codeForbidden = 403
	codeNotFound  = 404
	codeGone      = 410
)

// File is the result for one path, relative to the portal base.
type File struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Manifest is the result of checking the embedded files against a manifest.
type Manifest struct {
	Source     string   `json:"source"`
	Status     string   `json:"status"`
	Mismatches []string `json:"mismatches,omitempty"`
}

// Report is the whole result.
type Report struct {
	PortalURL string    `json:"portalUrl"`
	OK        bool      `json:"ok"`
	Checked   int       `json:"checked"`
	Files     []File    `json:"files"`
	Manifest  *Manifest `json:"manifest,omitempty"`
}

// PortalverifyOptions configures Verify.
type PortalverifyOptions struct {
	// Base is the portal origin, without a trailing slash.
	Base string
	// Files is the embedded copy; every regular file in it is checked.
	Files fs.FS
	// Fetch fetches the portal's paths (out/portalfetch for Base); required.
	Fetch PageFetcher
	// Headers are the response headers every file must carry; only
	// Content-Security-Policy is compared, plus the media type of .js.
	Headers textproto.MIMEHeader
	// FileHeaders replace Headers for one embedded file, by its path, and
	// for every route to it: the connect page has its own policy. A
	// Cache-Control in them must be served with each of its directives.
	FileHeaders map[string]textproto.MIMEHeader
	// Routes are the paths people load a page at (the engine's PageRoutes,
	// which the portal's _redirects rewrites to page files). Each is fetched
	// and compared with its embedded File, so a rewrite to another page is
	// seen.
	Routes []Route
	// Manifest, when set, is a "sha256  path" list the embedded files are
	// checked against; ManifestSource names it in the report.
	Manifest       []byte
	ManifestSource string
}

// Route is a path a page is served at: Path, or Path followed by an id
// (Path ends in a slash) when ID is set,
// with the bytes of File.
type Route struct {
	Path string
	ID   bool
	File string
}

// notFoundFile is the portal's not-found page. Its host serves it, with
// status 404, at every path it has no file for, so Verify checks it at
// notFoundPath rather than at its own path.
const notFoundFile = "404.html"

// notFoundPath is a path no portal file or rewrite answers.
const notFoundPath = "/basalt-portal-verify-no-such-page"

// probeID stands in for the id of an ID route; the portal's static rewrite
// ignores it.
const probeID = "00000000-0000-7000-8000-000000000000"

// ValidateURL accepts an https URL, or an http URL on a loopback host (a
// test server), with no path, query, fragment or credentials. It returns
// the origin without a trailing slash.
func ValidateURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("%q is not a URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%q must be an origin only (scheme, host, port)", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("%q: http is allowed only for a loopback host", raw)
		}
	default:
		return "", fmt.Errorf("%q must start with https://", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// probes are paths the portal build never publishes (tests and Go files); a
// host that serves one has more than the page files on it. A static host
// has no listing, so these named paths are all that can be checked.
func probes(embedded []string) []string {
	out := []string{"embed.go", "embed_test.go"}
	for _, p := range embedded {
		if strings.HasPrefix(p, "lib/") && strings.HasSuffix(p, ".js") {
			out = append(out, strings.TrimSuffix(p, ".js")+".test.mjs")
		}
	}
	return out
}

// requestPath is the URL path of an embedded file: a directory's
// index.html is served at the directory.
func requestPath(p string) string {
	if p == "index.html" {
		return ""
	}
	if strings.HasSuffix(p, "/index.html") {
		return strings.TrimSuffix(p, "index.html")
	}
	return p
}

// embedded lists the regular files of fsys, sorted.
func embedded(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return err
	})
	slices.Sort(out)
	return out, err
}

// Verify checks every embedded file against the portal.
func Verify(ctx context.Context, o PortalverifyOptions) (*Report, error) {
	paths, err := embedded(o.Files)
	if err != nil {
		return nil, err
	}
	client := o.Fetch
	if client == nil {
		return nil, errors.New("status: the portal check has no fetcher")
	}
	r := &Report{PortalURL: o.Base, Files: make([]File, 0, len(paths))}
	for _, p := range paths {
		want, err := fs.ReadFile(o.Files, p)
		if err != nil {
			return nil, err
		}
		if p == notFoundFile {
			r.Files = append(r.Files, checkNotFound(ctx, client, o, want))
			continue
		}
		r.Files = append(r.Files, checkFile(ctx, client, p, "/"+requestPath(p), want, o.headersFor(p)))
	}
	for _, rt := range o.Routes {
		want, err := fs.ReadFile(o.Files, rt.File)
		if err != nil {
			return nil, err
		}
		u := rt.Path
		if rt.ID {
			u += probeID
		}
		r.Files = append(r.Files, checkFile(ctx, client, u, u, want, o.headersFor(rt.File)))
	}
	for _, p := range probes(paths) {
		if f, bad := checkExtra(ctx, client, p); bad {
			r.Files = append(r.Files, f)
		}
	}
	r.Checked = len(paths)
	if o.Manifest != nil {
		m := checkManifest(o.Files, paths, o.Manifest)
		m.Source = o.ManifestSource
		r.Manifest = &m
	}
	r.OK = r.Manifest == nil || r.Manifest.Status == StatusOK
	for _, f := range r.Files {
		if f.Status != StatusOK {
			r.OK = false
		}
	}
	return r, nil
}

// answer is what one GET returned, with the body already read and closed.
type answer struct {
	status int
	header textproto.MIMEHeader
	body   []byte
}

// get fetches urlPath through c, reading at most maxBody+1 bytes of its body.
func get(ctx context.Context, c PageFetcher, urlPath string) (answer, error) {
	code, header, body, err := c.Get(ctx, urlPath, maxBody+1)
	return answer{code, header, body}, err
}

// headersFor is the header set the embedded file p must be served with.
func (o PortalverifyOptions) headersFor(p string) textproto.MIMEHeader {
	if h, ok := o.FileHeaders[p]; ok {
		return h
	}
	return o.Headers
}

// checkFile fetches urlPath and compares it with want and its headers with
// hdr; p names the result.
func checkFile(ctx context.Context, c PageFetcher, p, urlPath string, want []byte, hdr textproto.MIMEHeader) File {
	a, err := get(ctx, c, urlPath)
	if err != nil {
		return File{Path: p, Status: StatusError, Detail: err.Error()}
	}
	switch {
	case a.status == codeNotFound:
		return File{Path: p, Status: StatusMissing}
	case a.status != codeOK:
		return File{Path: p, Status: StatusError, Detail: fmt.Sprintf("HTTP %d", a.status)}
	}
	return compare(p, a, want, hdr)
}

// compare checks a served answer's bytes against want, then its headers
// against hdr.
func compare(p string, a answer, want []byte, hdr textproto.MIMEHeader) File {
	if len(a.body) > maxBody || sum(a.body) != sum(want) {
		return File{Path: p, Status: StatusDiffers, Detail: fmt.Sprintf("served sha256 %s, embedded %s", short(a.body), short(want))}
	}
	if d := headerProblem(a.header, hdr, p); d != "" {
		return File{Path: p, Status: StatusHeader, Detail: d}
	}
	return File{Path: p, Status: StatusOK}
}

// checkNotFound fetches notFoundPath and wants status 404 with the bytes of
// the not-found page. A 200 means the host answers unknown paths with
// something else (a single-page fallback to the home page, say), which would
// also hide the probes for files it must not serve; any other status is
// reported as an error.
func checkNotFound(ctx context.Context, c PageFetcher, o PortalverifyOptions, want []byte) File {
	a, err := get(ctx, c, notFoundPath)
	if err != nil {
		return File{Path: notFoundFile, Status: StatusError, Detail: err.Error()}
	}
	switch {
	case a.status == codeOK:
		return File{Path: notFoundFile, Status: StatusDiffers, Detail: fmt.Sprintf("HTTP %d at %s, want 404 with this page", a.status, notFoundPath)}
	case a.status != codeNotFound:
		return File{Path: notFoundFile, Status: StatusError, Detail: fmt.Sprintf("HTTP %d at %s", a.status, notFoundPath)}
	}
	return compare(notFoundFile, a, want, o.headersFor(notFoundFile))
}

// headerProblem names the first wrong header: the CSP must equal the
// wanted one, a wanted Cache-Control's directives must all be served, and a
// .js file must be text/javascript.
func headerProblem(got, want textproto.MIMEHeader, p string) string {
	if csp := want.Get("Content-Security-Policy"); csp != "" {
		switch have := got.Get("Content-Security-Policy"); {
		case have == "":
			return "Content-Security-Policy is absent"
		case have != csp:
			return fmt.Sprintf("Content-Security-Policy is %q, want %q", have, csp)
		}
	}
	if cc := want.Get("Cache-Control"); cc != "" {
		have := directives(got.Values("Cache-Control"))
		for d := range directives([]string{cc}) {
			if !have[d] {
				return fmt.Sprintf("Cache-Control is %q, want %q", strings.Join(got.Values("Cache-Control"), ", "), cc)
			}
		}
	}
	if path.Ext(p) == ".js" {
		mt, _, _ := mime.ParseMediaType(got.Get("Content-Type"))
		if mt != "text/javascript" {
			return fmt.Sprintf("Content-Type is %q, want text/javascript", got.Get("Content-Type"))
		}
	}
	return ""
}

// directives reads Cache-Control values into their lower-cased directives.
func directives(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		for _, d := range strings.Split(v, ",") {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				out[d] = true
			}
		}
	}
	return out
}

func checkExtra(ctx context.Context, c PageFetcher, p string) (File, bool) {
	a, err := get(ctx, c, "/"+p)
	switch {
	case err != nil:
		return File{Path: p, Status: StatusError, Detail: err.Error()}, true
	case a.status == codeOK:
		return File{Path: p, Status: StatusUnexpected, Detail: "served, but the binary does not embed it"}, true
	case a.status == codeNotFound, a.status == codeForbidden, a.status == codeGone:
		return File{}, false
	}
	return File{Path: p, Status: StatusError, Detail: fmt.Sprintf("HTTP %d", a.status)}, true
}

func sum(b []byte) [32]byte { return sha256.Sum256(b) }

func short(b []byte) string {
	s := sum(b)
	return hex.EncodeToString(s[:])[:12]
}

// ParseManifest reads "sha256  path" lines.
func ParseManifest(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		h, p, ok := strings.Cut(line, "  ")
		if !ok || len(h) != 64 || p == "" {
			return nil, fmt.Errorf("manifest line %d: want \"<sha256>  <path>\"", i+1)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("manifest line %d: bad sha256", i+1)
		}
		if _, dup := out[p]; dup {
			return nil, fmt.Errorf("manifest line %d: %s is listed twice", i+1, p)
		}
		out[p] = strings.ToLower(h)
	}
	return out, nil
}

func checkManifest(fsys fs.FS, paths []string, raw []byte) Manifest {
	want, err := ParseManifest(raw)
	if err != nil {
		return Manifest{Status: StatusError, Mismatches: []string{err.Error()}}
	}
	var bad []string
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			bad = append(bad, p+": "+err.Error())
			continue
		}
		s := sum(b)
		switch h, ok := want[p]; {
		case !ok:
			bad = append(bad, p+": not in the manifest")
		case h != hex.EncodeToString(s[:]):
			bad = append(bad, p+": differs from the manifest")
		}
	}
	for p := range want {
		if !seen[p] {
			bad = append(bad, p+": in the manifest, not embedded")
		}
	}
	slices.Sort(bad)
	if len(bad) > 0 {
		return Manifest{Status: StatusDiffers, Mismatches: bad}
	}
	return Manifest{Status: StatusOK}
}
