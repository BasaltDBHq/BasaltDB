package logredact_test

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/lib/logredact"
)

const (
	secret = "Zm9vYmFyYmF6cXV4cXV1eA"
	page   = "http://localhost:7300/approvals/0193a4c2-7d1e-7c3a-9f00-0000000000d4"
)

// handlers are the two slog handlers the package builds.
var handlers = map[string]func(io.Writer) slog.Handler{
	"text": func(w io.Writer) slog.Handler { return logredact.NewTextHandler(w, nil) },
	"json": func(w io.Writer) slog.Handler { return logredact.NewJSONHandler(w, nil) },
}

type withURL struct{ Link string }

// logLinkSecrets logs a short link's secret, a hash link's hash and a page
// socket's token every way a log line can carry them: as a string, in the
// message, inside an error (wrapped too), percent-encoded in another URL,
// nested in a group, a struct and a map, through With, and a LinkToken an
// error wraps with %v. It returns what each handler wrote, and the secrets
// none of it may show.
func logLinkSecrets(t *testing.T, h slog.Handler) []string {
	t.Helper()
	var tok channel.LinkToken
	for i := range tok {
		tok[i] = byte(0x41 + i)
	}
	short := links.WithSecret(page, secret)
	hashLink, _, err := links.HashLink(page+"#1.eyJyZXF1ZXN0IjoibG9uZyJ9", "basalt-approval.txt")
	require.NoError(t, err)
	_, hash, ok := strings.Cut(hashLink, "#h=")
	require.True(t, ok, hashLink)
	socket := "ws://vault.example.com/v1/links/" + tok.Wire()

	log := slog.New(h)
	log.Info("link", "url", short)
	log.Info("issued " + short)
	log.Warn("failed", "err", fmt.Errorf("open %s: %w", short, errors.New("refused")))
	log.Warn("failed", "err", fmt.Errorf("outer: %w", fmt.Errorf("inner %s", hashLink)))
	log.Warn("dial", "err", fmt.Errorf("dial %s: refused", socket))
	log.Info("nested", slog.Group("g", "url", short, slog.Group("h", "err", errors.New(hashLink))))
	log.Info("struct", "v", withURL{Link: short}, "m", map[string]string{"link": hashLink})
	log.Info("escaped", "next", "http://localhost:7300/login?next="+url.QueryEscape(short))
	log.With("url", short).Info("with")
	log.Warn("token", "err", fmt.Errorf("register %v: refused", tok))
	return []string{secret, hash, tok.Wire()}
}

func TestHandlersRedactLinkSecrets(t *testing.T) {
	t.Parallel()
	for name, h := range handlers {
		var out bytes.Buffer
		for _, s := range logLinkSecrets(t, h(&out)) {
			require.NotContains(t, out.String(), s, "%s handler:\n%s", name, out.String())
		}
		require.Contains(t, out.String(), "#s="+logredact.Redacted, name)
		require.Contains(t, out.String(), "#h="+logredact.Redacted, name)
		require.Contains(t, out.String(), "/v1/links/"+logredact.Redacted, name)
		require.Contains(t, out.String(), "%23s%3D"+logredact.Redacted, name)
		require.Contains(t, out.String(), "/approvals/0193a4c2-7d1e-7c3a-9f00-0000000000d4", "%s: the page stays", name)
		require.Contains(t, out.String(), "refused", "%s: the error's text stays", name)
	}
}

// The JSON handler follows a pointer that %+v prints as an address: a
// struct whose pointer field holds a link is scrubbed too.
func TestJSONHandlerScrubsThroughPointers(t *testing.T) {
	t.Parallel()
	short := links.WithSecret(page, secret)
	for name, h := range handlers {
		var out bytes.Buffer
		slog.New(h(&out)).Info("m", "v", struct{ P *string }{&short})
		require.NotContains(t, out.String(), secret, "%s: %s", name, out.String())
	}
}

// A value with no secret in it is logged as it was: an error stays an error,
// a struct keeps the JSON handler's object form.
func TestHandlersLeaveOtherValuesAlone(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	log := slog.New(logredact.NewJSONHandler(&out, nil))
	log.Info("plain", "url", page, "n", 3, "v", withURL{Link: page}, "err", errors.New("no #secret here"))
	require.Contains(t, out.String(), `"url":"`+page+`"`)
	require.Contains(t, out.String(), `"n":3`)
	require.Contains(t, out.String(), `"v":{"Link":"`+page+`"}`)
	require.Contains(t, out.String(), `"err":"no #secret here"`)
}

// The caller's own ReplaceAttr still runs, before the scrub.
func TestHandlersKeepTheCallersReplaceAttr(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	opts := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == "short" {
			a.Value = slog.StringValue(links.WithSecret(page, secret))
		}
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	slog.New(logredact.NewTextHandler(&out, opts)).Info("m", "short", "x")
	require.NotContains(t, out.String(), secret)
	require.NotContains(t, out.String(), "time=")
}

func TestScrub(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		page + "#s=" + secret:                        page + "#s=[redacted]",
		page + "#s=" + secret + " and more":          page + "#s=[redacted] and more",
		page + "#h=abc-_123":                         page + "#h=[redacted]",
		"next=" + url.QueryEscape(page+"#s="+secret): "next=" + url.QueryEscape(page) + "%23s%3D[redacted]",
		"x%23s%3d" + secret:                          "x%23s%3d[redacted]",
		"wss://v/v1/links/" + secret + "?a=1":        "wss://v/v1/links/[redacted]?a=1",
		page + "#1.eyJhIjoxfQ":                       page + "#1.eyJhIjoxfQ",
		"nothing here":                               "nothing here",
	} {
		require.Equal(t, want, logredact.Scrub(in), in)
	}
}

// Every slog handler production code builds comes from this package: a
// slog.NewTextHandler or slog.NewJSONHandler anywhere else in cmd or
// internal (tests aside) fails here.
func TestEveryProductionHandlerIsRedacted(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	var stray []string
	for _, dir := range []string{"cmd", "internal"} {
		require.NoError(t, filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "logredact" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			require.NoError(t, err)
			f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
			require.NoError(t, err)
			stray = append(stray, plainHandlers(path, f)...)
			return nil
		}))
	}
	require.Empty(t, stray, "build slog handlers with logredact.NewTextHandler or NewJSONHandler")
}

// plainHandlers is every reference to slog.NewTextHandler or
// slog.NewJSONHandler in f, under any name log/slog is imported as.
func plainHandlers(path string, f *ast.File) []string {
	names, dot := map[string]bool{}, false
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != "log/slog" {
			continue
		}
		switch {
		case imp.Name == nil:
			names["slog"] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	plain := map[string]bool{"NewTextHandler": true, "NewJSONHandler": true}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := n.X.(*ast.Ident); ok && names[id.Name] && plain[n.Sel.Name] {
				found = append(found, path+": "+id.Name+"."+n.Sel.Name)
			}
		case *ast.Ident:
			if dot && plain[n.Name] {
				found = append(found, path+": "+n.Name)
			}
		}
		return true
	})
	return found
}

func TestPlainHandlersSeesEveryImportName(t *testing.T) {
	t.Parallel()
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		require.NoError(t, err)
		return f
	}
	require.Len(t, plainHandlers("x.go", parse(`package x
import "log/slog"
var a = slog.NewTextHandler
func b() { slog.New(slog.NewJSONHandler(nil, nil)) }
`)), 2)
	require.Len(t, plainHandlers("x.go", parse(`package x
import l "log/slog"
func b() { l.NewJSONHandler(nil, nil) }
`)), 1)
	require.Len(t, plainHandlers("x.go", parse(`package x
import . "log/slog"
func b() { NewTextHandler(nil, nil) }
`)), 1)
	require.Empty(t, plainHandlers("x.go", parse(`package x
import "log/slog"
func b() { slog.New(slog.DiscardHandler); logredact.NewTextHandler(nil, nil) }
`)))
}
