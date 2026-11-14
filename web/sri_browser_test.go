package web_test

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/websec"
	"github.com/basaltdbhq/basaltdb/web"
)

// headlessBrowser finds a Chromium that can run headless: $BASALT_TEST_BROWSER,
// then Playwright's cached chromium-headless-shell or chromium, then a Chrome
// or Chromium on the PATH or in /Applications. It returns "" when none is
// found.
func headlessBrowser() string {
	if p := os.Getenv("BASALT_TEST_BROWSER"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	caches := []string{os.Getenv("PLAYWRIGHT_BROWSERS_PATH")}
	if runtime.GOOS == "darwin" {
		caches = append(caches, filepath.Join(home, "Library", "Caches", "ms-playwright"))
	} else {
		caches = append(caches, filepath.Join(home, ".cache", "ms-playwright"))
	}
	for _, c := range caches {
		if c == "" {
			continue
		}
		for _, pattern := range []string{
			"chromium_headless_shell-*/chrome-headless-shell-*/chrome-headless-shell",
			"chromium-*/chrome-linux*/chrome",
			"chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium",
			"chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		} {
			if m, _ := filepath.Glob(filepath.Join(c, pattern)); len(m) > 0 {
				return m[len(m)-1]
			}
		}
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// dumpDOM loads url in a headless browser and returns the DOM after the load
// event (module scripts have run by then) and what the browser logged. A
// browser that hangs (seen on a loaded machine) is killed and started once
// more; any other failure fails the test.
func dumpDOM(t *testing.T, browser, url string) (dom, log string) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		dom, log, err := runBrowser(t, browser, url)
		if err == nil {
			return dom, log
		}
		if !errors.Is(err, context.DeadlineExceeded) || attempt == 2 {
			require.NoError(t, err, "browser: %s", log)
		}
		t.Logf("browser timed out, starting it again")
	}
}

func runBrowser(t *testing.T, browser, url string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, browser, // #nosec G204 -- the browser path is the tester's
		"--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--user-data-dir="+t.TempDir(), "--enable-logging=stderr", "--v=0",
		"--virtual-time-budget=5000", "--dump-dom", url)
	if runtime.GOOS == "linux" {
		// CI runners (and root) often cannot start Chromium's sandbox; the
		// pages loaded here are the repository's own, served on localhost.
		cmd.Args = append(cmd.Args, "--no-sandbox")
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return out.String(), errb.String(), err
}

func copyFiles(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	require.NoError(t, fs.WalkDir(web.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(web.Files, p)
		m[p] = &fstest.MapFile{Data: b}
		return err
	}))
	return m
}

// serve serves files the way the engine does (its security headers, the
// strict CSP among them) on a localhost origin the pages accept.
func serve(t *testing.T, files fs.FS) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(websec.Headers()(http.FileServerFS(files)))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return "http://localhost:" + strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
}

// A wrong integrity hash must stop the page's script in a real browser, not
// only in the Go check: the approve page, served with the engine's headers,
// runs its script when every hash matches (the script reports the missing
// approval id), and runs nothing when a module was swapped behind an
// unchanged page or the page carries a wrong hash for its entry script.
//
// It needs a headless Chromium and skips without one. To run it:
//
//	npx playwright install chromium-headless-shell
//	go test -count=1 -run TestPortalSRIBlocksScriptInBrowser -v ./web
//
// or point BASALT_TEST_BROWSER at any Chrome or Chromium binary.
// BASALT_TEST_BROWSER=none skips it.
func TestPortalSRIBlocksScriptInBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a browser; skipped with -short")
	}
	browser := headlessBrowser()
	if browser == "" || browser == "none" {
		t.Skip("no headless Chromium found: run `npx playwright install chromium-headless-shell` or set BASALT_TEST_BROWSER to a Chrome or Chromium binary")
	}
	t.Logf("browser: %s", browser)
	const page = "approve/index.html"
	ran := regexp.MustCompile(`<p id="error-text">[^<]*cannot be used[^<]*</p>`)
	idle := `<p id="error-text"></p>`

	wrong := sha512.Sum384([]byte("not the script"))
	wrongHash := "sha384-" + base64.StdEncoding.EncodeToString(wrong[:])

	cases := []struct {
		name    string
		edit    func(fstest.MapFS)
		blocked string // the file the browser must refuse, "" when none
	}{
		{"every hash matches", func(fstest.MapFS) {}, ""},
		{"an imported module swapped, page unchanged", func(m fstest.MapFS) {
			m["lib/page.js"] = &fstest.MapFile{Data: append(bytes.Clone(m["lib/page.js"].Data), "\n// swapped\n"...)}
		}, "lib/page.js"},
		{"the entry script swapped, page unchanged", func(m fstest.MapFS) {
			m["lib/approve.js"] = &fstest.MapFile{Data: append(bytes.Clone(m["lib/approve.js"].Data), "\n// swapped\n"...)}
		}, "lib/approve.js"},
		{"a wrong hash for the entry script in the page", func(m fstest.MapFS) {
			good, err := sri(m, "lib/approve.js")
			require.NoError(t, err)
			html := string(m[page].Data)
			require.Contains(t, html, good)
			m[page] = &fstest.MapFile{Data: []byte(strings.Replace(html, good, wrongHash, 1))}
		}, "lib/approve.js"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := copyFiles(t)
			c.edit(files)
			dom, log := dumpDOM(t, browser, serve(t, files)+"/approve/")
			if c.blocked == "" {
				require.Regexp(t, ran, dom, "the page script did not run; browser log:\n%s", log)
				require.NotContains(t, log, "integrity")
				return
			}
			require.NotRegexp(t, ran, dom, "the page script ran although %s does not match its hash", c.blocked)
			require.Contains(t, dom, idle)
			require.Regexp(t, regexp.MustCompile(`integrity[^\n]*/`+regexp.QuoteMeta(c.blocked)+`[^\n]*blocked`), log,
				"the browser did not report blocking %s for its integrity", c.blocked)
		})
	}
}
